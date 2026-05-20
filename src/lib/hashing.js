// ============================================================================
// ThreadOS Core - PII Hashing Module
// ============================================================================
//
// Pure functions for hashing PII and producing sanitized display values.
//
// These functions are the lowest-level building blocks of identity handling
// in Core. They are deterministic, side-effect-free, and do not touch the
// database or any external services.
//
// Bible reference: Decision 1 (HMAC-SHA256), Decision 2 (deterministic
// matching), and the architectural principle that raw PII is never displayed.
// ============================================================================

const crypto = require('crypto');

// ----------------------------------------------------------------------------
// Salt resolution
// ----------------------------------------------------------------------------
//
// The HMAC salt must be configured before any hashing happens. We resolve it
// lazily (on first hash) rather than at module load, so that test setups can
// override the salt before calling these functions.
//
// We also cache the resolved salt to avoid repeatedly checking process.env.
// ----------------------------------------------------------------------------

let _cachedSalt = null;

function getSalt() {
    if (_cachedSalt !== null) {
        return _cachedSalt;
    }

    const salt = process.env.PII_HASH_SALT;

    if (!salt || salt.trim() === '') {
        throw new Error(
            'PII_HASH_SALT environment variable is not set. ' +
            'Identity hashing cannot proceed without a configured salt.'
        );
    }

    _cachedSalt = salt;
    return salt;
}

// Test helper: reset the cached salt so tests can change it between cases.
// Not exposed in normal usage.
function _resetSaltCache() {
    _cachedSalt = null;
}

// ----------------------------------------------------------------------------
// hashPII
// ----------------------------------------------------------------------------
//
// HMAC-SHA256 hash of a normalized PII value.
//
// Returns null for null/empty input. Otherwise returns a 64-character hex
// string. The same input always produces the same output (deterministic).
//
// Normalization: lowercase, trim whitespace. This ensures
//   "jane@example.com" and "JANE@example.com" produce the same hash.
//
// Note: for phone numbers, the caller should strip non-digits first by
// passing the result of normalizePhone() in. We don't do that here because
// hashPII is generic — it doesn't know if it's hashing an email or a phone.
// ----------------------------------------------------------------------------

function hashPII(value) {
    if (value === null || value === undefined || value === '') {
        return null;
    }

    const normalized = String(value).trim().toLowerCase();

    if (normalized === '') {
        return null;
    }

    const hmac = crypto.createHmac('sha256', getSalt());
    hmac.update(normalized);
    return hmac.digest('hex');
}

// ----------------------------------------------------------------------------
// normalizePhone
// ----------------------------------------------------------------------------
//
// Strips all non-digit characters from a phone number. Useful for
// normalizing phone numbers before hashing them, so that
//   "(555) 123-4567" and "555-123-4567" and "5551234567"
// all produce the same hash.
//
// Returns null if the input has fewer than 10 digits after stripping,
// since that's not a valid phone number for our purposes.
// ----------------------------------------------------------------------------

function normalizePhone(phone) {
    if (phone === null || phone === undefined || phone === '') {
        return null;
    }

    const digits = String(phone).replace(/\D/g, '');

    if (digits.length < 10) {
        return null;
    }

    return digits;
}

// ----------------------------------------------------------------------------
// generateResolutionKey
// ----------------------------------------------------------------------------
//
// Combines available hashed identifiers into a single deterministic lookup
// key. Used to find an existing identity record when we may have email,
// phone, or both.
//
// Note: this is plain SHA-256 (not HMAC), because the resolution key itself
// is not PII — it's a derived value. The privacy protection comes from the
// fact that its inputs are already hashed PII.
//
// At least one of emailHash or phoneHash must be provided.
// ----------------------------------------------------------------------------

function generateResolutionKey(emailHash, phoneHash) {
    if (!emailHash && !phoneHash) {
        throw new Error(
            'generateResolutionKey requires at least one of emailHash or phoneHash'
        );
    }

    const combined = `${emailHash || 'NONE'}|${phoneHash || 'NONE'}`;

    const hash = crypto.createHash('sha256');
    hash.update(combined);
    return hash.digest('hex');
}

// ----------------------------------------------------------------------------
// sanitizeEmail
// ----------------------------------------------------------------------------
//
// Produces a display-safe version of an email address:
//   "jane@example.com"      -> "j***@example.com"
//   "j@example.com"         -> "j@example.com"     (single char, no masking)
//   "verylongname@x.com"    -> "v*****@x.com"      (capped at 5 asterisks)
//   "not-an-email"          -> "***@***.***"       (malformed fallback)
//
// Returns null for null/empty input.
// ----------------------------------------------------------------------------

function sanitizeEmail(email) {
    if (email === null || email === undefined || email === '') {
        return null;
    }

    const value = String(email).trim();

    if (!value.includes('@')) {
        return '***@***.***';
    }

    const parts = value.split('@');

    if (parts.length !== 2 || parts[0].length === 0 || parts[1].length === 0) {
        return '***@***.***';
    }

    const [username, domain] = parts;

    if (username.length <= 1) {
        return `${username}@${domain}`;
    }

    const maskedLength = Math.min(username.length - 1, 5);
    const masked = username[0] + '*'.repeat(maskedLength);

    return `${masked}@${domain}`;
}

// ----------------------------------------------------------------------------
// sanitizePhone
// ----------------------------------------------------------------------------
//
// Produces a display-safe version of a phone number:
//   "5551234567"      -> "***-***-4567"
//   "(555) 123-4567"  -> "***-***-4567"
//   "+1-555-123-4567" -> "***-***-4567"
//   "12345"           -> null         (too short to be valid)
//
// Returns null for null/empty/invalid input.
// ----------------------------------------------------------------------------

function sanitizePhone(phone) {
    if (phone === null || phone === undefined || phone === '') {
        return null;
    }

    const digits = String(phone).replace(/\D/g, '');

    if (digits.length < 10) {
        return null;
    }

    return `***-***-${digits.slice(-4)}`;
}

// ----------------------------------------------------------------------------
// Exports
// ----------------------------------------------------------------------------

module.exports = {
    hashPII,
    normalizePhone,
    generateResolutionKey,
    sanitizeEmail,
    sanitizePhone,
    // Internal: exposed only for testing
    _resetSaltCache,
};
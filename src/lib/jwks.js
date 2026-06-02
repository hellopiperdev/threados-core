// ============================================================================
// ThreadOS Core - JWKS (JSON Web Key Set) Utilities
// ============================================================================
//
// Two responsibilities:
//
// 1. Serving Core's own public key(s) as a JWKS document via an HTTP
//    endpoint. This is what other services would call to verify tokens
//    Core might sign in the future.
//
// 2. Fetching and caching JWKS documents from registered verticals. Used
//    during JWT verification to find the public key that matches the
//    incoming token's `kid` claim.
//
// Bible reference:
//   Decision 18: Service-to-service auth via signed JWT
// ============================================================================

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ----------------------------------------------------------------------------
// Configuration
// ----------------------------------------------------------------------------

const KEYS_DIR = path.join(__dirname, '..', '..', 'keys');
const CORE_KEY_NAME = 'threados-core';

// ----------------------------------------------------------------------------
// PEM to JWKS conversion
// ----------------------------------------------------------------------------
//
// Converts an Ed25519 public key in PEM format to the JWKS format defined
// by RFC 8037 (CFRG Elliptic Curve Diffie-Hellman and Signatures in JSON
// Object Signing and Encryption).
//
// Returns an object with the standard JWKS fields for an Ed25519 key.
// ----------------------------------------------------------------------------

function pemPublicKeyToJwk(pem, kid) {
    const keyObject = crypto.createPublicKey(pem);

    if (keyObject.asymmetricKeyType !== 'ed25519') {
        throw new Error(
            `Expected Ed25519 key, got ${keyObject.asymmetricKeyType}`
        );
    }

    // Export as JWK directly - Node's crypto API knows how to do this
    const jwk = keyObject.export({ format: 'jwk' });

    // Add the standard fields beyond what crypto.export provides
    return {
        kty: jwk.kty,      // 'OKP' for Ed25519
        crv: jwk.crv,      // 'Ed25519'
        x: jwk.x,          // base64url-encoded public key bytes
        kid: kid,          // key id
        alg: 'EdDSA',
        use: 'sig',
    };
}

// ----------------------------------------------------------------------------
// Compute a stable key ID from the key material
// ----------------------------------------------------------------------------
//
// The kid (key ID) is what JWT headers reference to indicate which key
// was used to sign. We derive it deterministically from the key material
// so it stays stable across server restarts but changes when the key
// changes (e.g., after rotation).
//
// Uses a SHA-256 truncated to 16 chars for readability.
// ----------------------------------------------------------------------------

function computeKid(pemPublicKey) {
    return crypto
        .createHash('sha256')
        .update(pemPublicKey)
        .digest('hex')
        .slice(0, 16);
}

// ----------------------------------------------------------------------------
// Get Core's own JWKS document
// ----------------------------------------------------------------------------
//
// Reads Core's public key from disk, converts to JWKS format, and returns
// the document. Cached after first read (the key doesn't change at runtime).
//
// In production, the key would come from Secret Manager rather than disk.
// That migration would happen in src/lib/secrets.js, not here.
// ----------------------------------------------------------------------------

let _coreJwksCache = null;

function getCoreJwks() {
    if (_coreJwksCache !== null) {
        return _coreJwksCache;
    }

    const publicKeyPath = path.join(KEYS_DIR, CORE_KEY_NAME, 'public.pem');

    if (!fs.existsSync(publicKeyPath)) {
        throw new Error(
            `Core public key not found at ${publicKeyPath}. ` +
            `Run: node scripts/generate-keys.js ${CORE_KEY_NAME}`
        );
    }

    const pem = fs.readFileSync(publicKeyPath, 'utf8');
    const kid = computeKid(pem);
    const jwk = pemPublicKeyToJwk(pem, kid);

    _coreJwksCache = {
        keys: [jwk],
    };

    return _coreJwksCache;
}

// ----------------------------------------------------------------------------
// JWKS fetching and caching (for verticals)
// ----------------------------------------------------------------------------
//
// Cache structure: { [jwksUrl]: { jwks, fetchedAt, ttlSeconds } }
//
// Lookup flow:
//   1. Check cache for the URL
//   2. If present AND not expired, return cached value
//   3. Otherwise fetch fresh, cache, and return
//   4. On fetch failure, throw - strict failure mode (Bible decision)
// ----------------------------------------------------------------------------

const _verticalJwksCache = new Map();

function _isCacheEntryValid(entry) {
    if (!entry) return false;
    const ageSeconds = (Date.now() - entry.fetchedAt) / 1000;
    return ageSeconds < entry.ttlSeconds;
}

async function fetchJwks(url) {
    let response;
    try {
        response = await fetch(url, {
            method: 'GET',
            headers: { 'Accept': 'application/json' },
            // Reasonable timeout - we don't want to hang forever
            signal: AbortSignal.timeout(5000),
        });
    } catch (err) {
        throw new Error(`JWKS fetch failed for ${url}: ${err.message}`);
    }

    if (!response.ok) {
        throw new Error(
            `JWKS fetch returned ${response.status} for ${url}`
        );
    }

    let body;
    try {
        body = await response.json();
    } catch (err) {
        throw new Error(`JWKS response is not valid JSON for ${url}`);
    }

    if (!body.keys || !Array.isArray(body.keys)) {
        throw new Error(
            `JWKS response missing "keys" array for ${url}`
        );
    }

    return body;
}

async function getJwksForVertical(jwksUrl, ttlSeconds = 3600) {
    const cached = _verticalJwksCache.get(jwksUrl);

    if (_isCacheEntryValid(cached)) {
        return cached.jwks;
    }

    // Fetch fresh
    const jwks = await fetchJwks(jwksUrl);

    _verticalJwksCache.set(jwksUrl, {
        jwks,
        fetchedAt: Date.now(),
        ttlSeconds,
    });

    return jwks;
}

// ----------------------------------------------------------------------------
// Find a specific key in a JWKS document by kid
// ----------------------------------------------------------------------------
//
// Returns the JWK matching the given kid, or null if not found.
// ----------------------------------------------------------------------------

function findKeyByKid(jwks, kid) {
    if (!jwks || !Array.isArray(jwks.keys)) return null;
    return jwks.keys.find(k => k.kid === kid) || null;
}

// ----------------------------------------------------------------------------
// Test helpers
// ----------------------------------------------------------------------------

function _resetCoreJwksCache() {
    _coreJwksCache = null;
}

function _resetVerticalJwksCache() {
    _verticalJwksCache.clear();
}

// ----------------------------------------------------------------------------
// Exports
// ----------------------------------------------------------------------------

module.exports = {
    getCoreJwks,
    getJwksForVertical,
    findKeyByKid,
    pemPublicKeyToJwk,
    computeKid,
    // Internal: testing only
    _resetCoreJwksCache,
    _resetVerticalJwksCache,
};
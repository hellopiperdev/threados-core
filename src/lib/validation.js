// ============================================================================
// ThreadOS Core - Request Validation
// ============================================================================
//
// Functions for validating the shape of API request payloads.
//
// Validation here is about structure: are required fields present, are
// types correct, do values match expected formats. We do NOT validate
// semantic correctness (does this email exist, is this a real phone) -
// that's the application's job.
//
// Errors returned by these functions are designed to be clear and
// actionable for the caller, matching the Gatekeeper Principle from the
// Bible: "Core validates strictly. Rejects garbage. Returns actionable
// errors that tell the vertical exactly what was wrong."
//
// Each validator returns either:
//   { valid: true, value: <normalized value> }
//   { valid: false, error: { field, code, message } }
// ============================================================================

// ----------------------------------------------------------------------------
// Field-level validators
// ----------------------------------------------------------------------------
//
// Each returns { valid, value?, error? }
// - value is the (possibly normalized) value to use
// - error is a structured object with field, code, and message
// ----------------------------------------------------------------------------

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function validateEmail(value, fieldName = 'email') {
    if (value === undefined || value === null) {
        return { valid: true, value: null };
    }

    if (typeof value !== 'string') {
        return {
            valid: false,
            error: {
                field: fieldName,
                code: 'invalid_type',
                message: `${fieldName} must be a string`,
            },
        };
    }

    const trimmed = value.trim();

    if (trimmed === '') {
        return { valid: true, value: null };
    }

    if (trimmed.length > 320) {
        // 320 = max length per RFC 5321 (64 local + @ + 255 domain)
        return {
            valid: false,
            error: {
                field: fieldName,
                code: 'too_long',
                message: `${fieldName} must be 320 characters or fewer`,
            },
        };
    }

    if (!EMAIL_REGEX.test(trimmed)) {
        return {
            valid: false,
            error: {
                field: fieldName,
                code: 'invalid_format',
                message: `${fieldName} must be a valid email address`,
            },
        };
    }

    return { valid: true, value: trimmed };
}

function validatePhone(value, fieldName = 'phone') {
    if (value === undefined || value === null) {
        return { valid: true, value: null };
    }

    if (typeof value !== 'string') {
        return {
            valid: false,
            error: {
                field: fieldName,
                code: 'invalid_type',
                message: `${fieldName} must be a string`,
            },
        };
    }

    const trimmed = value.trim();

    if (trimmed === '') {
        return { valid: true, value: null };
    }

    // Permissive format check: must contain at least 10 digits, allowing
    // common separators and country code prefixes
    const digits = trimmed.replace(/\D/g, '');

    if (digits.length < 10) {
        return {
            valid: false,
            error: {
                field: fieldName,
                code: 'invalid_format',
                message: `${fieldName} must contain at least 10 digits`,
            },
        };
    }

    if (digits.length > 15) {
        // E.164 max length is 15 digits
        return {
            valid: false,
            error: {
                field: fieldName,
                code: 'invalid_format',
                message: `${fieldName} must contain 15 or fewer digits`,
            },
        };
    }

    return { valid: true, value: trimmed };
}

// Matches any ASCII control character (0x00-0x1F) except whitespace we
// consider acceptable (we permit tab and newline in case names span lines,
// though we mostly don't expect either), plus the DEL character (0x7F).
// Null bytes, vertical tabs, form feeds, etc. are rejected.
const CONTROL_CHAR_REGEX = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/;

function validateName(value, fieldName = 'name') {
    if (value === undefined || value === null) {
        return { valid: true, value: null };
    }

    if (typeof value !== 'string') {
        return {
            valid: false,
            error: {
                field: fieldName,
                code: 'invalid_type',
                message: `${fieldName} must be a string`,
            },
        };
    }

    if (CONTROL_CHAR_REGEX.test(value)) {
        return {
            valid: false,
            error: {
                field: fieldName,
                code: 'invalid_characters',
                message: `${fieldName} must not contain control characters`,
            },
        };
    }

    const trimmed = value.trim();

    if (trimmed === '') {
        return { valid: true, value: null };
    }

    if (trimmed.length > 200) {
        return {
            valid: false,
            error: {
                field: fieldName,
                code: 'too_long',
                message: `${fieldName} must be 200 characters or fewer`,
            },
        };
    }

    return { valid: true, value: trimmed };
}

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function validateUuid(value, fieldName) {
    if (value === undefined || value === null || value === '') {
        return {
            valid: false,
            error: {
                field: fieldName,
                code: 'missing',
                message: `${fieldName} is required`,
            },
        };
    }

    if (typeof value !== 'string') {
        return {
            valid: false,
            error: {
                field: fieldName,
                code: 'invalid_type',
                message: `${fieldName} must be a string`,
            },
        };
    }

    if (!UUID_REGEX.test(value)) {
        return {
            valid: false,
            error: {
                field: fieldName,
                code: 'invalid_format',
                message: `${fieldName} must be a valid UUID`,
            },
        };
    }

    return { valid: true, value: value.toLowerCase() };
}

// Optional opaque identifier: an ID minted by some external system whose format
// Core does not own and therefore cannot dictate. Session IDs (Express, Rails,
// frontend SDKs) and device fingerprints are opaque strings, not UUIDs. We only
// constrain what Core legitimately owns: it must be a non-empty, length-bounded
// string with no control characters (which would corrupt logs/storage). We do
// NOT impose a UUID or any other shape. Absent (undefined/null/empty) is fine.
function validateOptionalOpaqueId(value, fieldName, maxLength = 200) {
    if (value === undefined || value === null) {
        return { valid: true, value: null };
    }

    if (typeof value !== 'string') {
        return {
            valid: false,
            error: {
                field: fieldName,
                code: 'invalid_type',
                message: `${fieldName} must be a string`,
            },
        };
    }

    if (CONTROL_CHAR_REGEX.test(value)) {
        return {
            valid: false,
            error: {
                field: fieldName,
                code: 'invalid_characters',
                message: `${fieldName} must not contain control characters`,
            },
        };
    }

    const trimmed = value.trim();

    if (trimmed === '') {
        return {
            valid: false,
            error: {
                field: fieldName,
                code: 'missing',
                message: `${fieldName} must not be empty`,
            },
        };
    }

    if (trimmed.length > maxLength) {
        return {
            valid: false,
            error: {
                field: fieldName,
                code: 'too_long',
                message: `${fieldName} must be ${maxLength} characters or fewer`,
            },
        };
    }

    return { valid: true, value: trimmed };
}

// ----------------------------------------------------------------------------
// Composite validator for the identity/hash request
// ----------------------------------------------------------------------------
//
// Validates a request body shaped like:
//   { email?: string, phone?: string, name?: string }
//
// At least one of email or phone is required. Returns either:
//   { valid: true, value: { email, phone, name } }   - normalized values
//   { valid: false, errors: [...] }                  - one or more errors
// ----------------------------------------------------------------------------

function validateIdentityHashRequest(body) {
    if (!body || typeof body !== 'object') {
        return {
            valid: false,
            errors: [{
                field: 'body',
                code: 'invalid_type',
                message: 'request body must be a JSON object',
            }],
        };
    }

    const errors = [];

    const emailResult = validateEmail(body.email);
    if (!emailResult.valid) errors.push(emailResult.error);

    const phoneResult = validatePhone(body.phone);
    if (!phoneResult.valid) errors.push(phoneResult.error);

    const nameResult = validateName(body.name);
    if (!nameResult.valid) errors.push(nameResult.error);

    // If individual fields are valid, check that at least one identifier exists
    if (errors.length === 0) {
        const hasEmail = emailResult.value !== null;
        const hasPhone = phoneResult.value !== null;

        if (!hasEmail && !hasPhone) {
            errors.push({
                field: 'body',
                code: 'missing_identifier',
                message: 'at least one of email or phone is required',
            });
        }
    }

    if (errors.length > 0) {
        return { valid: false, errors };
    }

    return {
        valid: true,
        value: {
            email: emailResult.value,
            phone: phoneResult.value,
            name: nameResult.value,
        },
    };
}

// ----------------------------------------------------------------------------
// Exports
// ----------------------------------------------------------------------------

module.exports = {
    validateEmail,
    validatePhone,
    validateName,
    validateUuid,
    validateOptionalOpaqueId,
    validateIdentityHashRequest,
};
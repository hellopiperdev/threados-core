// ============================================================================
// ThreadOS Core - PII Detection
// ============================================================================
//
// Pattern-based detection of raw PII in free-form values. Extracted from
// src/lib/events.js (Step 7 Session 2) once a second caller appeared: event
// properties (Step 6) and consent capture_context / reason fields (Step 7)
// both need the same gatekeeping, and later free-text surfaces (audit notes,
// loyalty metadata) will too. PII has exactly one path into Core: the
// identity hashing API. Everything else gets scanned and rejected.
//
// Bible references:
//   Decision 7:  Opinionated gatekeeper - reject bad input with actionable
//                errors; never silently coerce or drop.
//   Decision 10: No raw PII outside the identity API - scan for
//                email/phone/SSN patterns and reject.
//
// The intent is not perfect PII classification - it's a gatekeeper that
// forces verticals to route identifying data through the identity hashing
// API instead of smuggling it inside free-form fields.
//
// Patterns are deliberately conservative-but-broad. A false positive (e.g. a
// 10-digit order number that looks like a phone) is an acceptable cost: the
// vertical gets a clear, actionable error and can restructure the field.
// We never echo the matched value back in errors - that would re-introduce the
// PII we're trying to keep out of logs and responses.
// ============================================================================

const PII_PATTERNS = [
    {
        type: 'email',
        // Local@domain.tld - same shape as the identity validator, unanchored
        // so it matches an address embedded anywhere in a larger string.
        regex: /[^\s@]+@[^\s@]+\.[^\s@]+/,
    },
    {
        type: 'ssn',
        // US Social Security Number: ###-##-#### (dashes or spaces). Checked
        // before phone so a dashed SSN is reported as an SSN, not a phone.
        regex: /\b\d{3}[-\s]\d{2}[-\s]\d{4}\b/,
    },
    {
        type: 'phone',
        // US/NANP phone numbers, deliberately narrowed to REQUIRE formatting so
        // we under-detect rather than over-detect (an MVP bias: a false positive
        // forces a vertical to restructure a legitimate property, which is real
        // friction). A bare run of 10 digits like "5551234567" - which is just as
        // likely an order number or numeric id - is intentionally NOT matched.
        //
        // To match, the number must be visibly phone-formatted: either a
        // parenthesized area code, or at least one dash/dot/space separating the
        // groups. An optional +1 / 1 country code is allowed.
        //   matches:    555-123-4567   (555) 123-4567   +1 555.123.4567
        //   no match:   5551234567     123456789012     12025551234 (unseparated)
        regex: /(?:\+?1[-.\s]?)?(?:\(\d{3}\)[-.\s]?|\d{3}[-.\s])\d{3}[-.\s]\d{4}/,
    },
    {
        type: 'phone',
        // International phone numbers in (loose) E.164 presentation: a leading +,
        // a 1-3 digit country code, then the national number written as digit
        // groups separated by spaces, dashes, or dots. The US/NANP pattern above
        // is formatting-specific and misses these entirely.
        //   matches:  +44 20 7946 0958 (UK)   +86 138 0000 0000 (China)
        //             +49 30 12345678 (Germany)   +1 555.123.4567
        //   no match: +1 (bare CC)   order+12 34 (too few national digits)
        //
        // Narrowing (yesterday's under-detect-over-over-detect bias): we REQUIRE a
        // separator immediately after the country code, then 7-14 national digits.
        // That keeps a bare "+1", or a + sitting next to a short number, from
        // tripping it, while still catching the grouped international formats we
        // verified slip through. Unseparated runs are handled by the pattern below.
        regex: /\+\d{1,3}[-.\s]\d(?:[-.\s]?\d){6,13}/,
    },
    {
        type: 'phone',
        // Unseparated international E.164: a leading + and 8-15 digits with no
        // separators at all (e.g. +442079460958, +8613800000000). Yesterday's
        // under-detect bias was specifically about bare digit runs WITHOUT a
        // leading + - order numbers and ids, where false positives are a real
        // risk. Once a + prefix is present, 8+ digits is either a phone number or
        // something genuinely weird, so the over-detection risk is narrow enough
        // to catch it. The 8-digit floor keeps "+1" and "+12345" (too short for
        // any real number) from tripping it.
        //   matches:  +442079460958 (UK)   +8613800000000 (China)
        //   no match: +1   +12345 (too short)
        regex: /\+\d{8,15}/,
    },
];

// Detect PII in a single scalar value. Returns the matched pattern type, or
// null if the value is clean.
function detectPiiInScalar(value) {
    if (typeof value !== 'string' && typeof value !== 'number') {
        return null;
    }
    const str = String(value);
    for (const { type, regex } of PII_PATTERNS) {
        if (regex.test(str)) {
            return type;
        }
    }
    return null;
}

// Recursively scan an arbitrary value for PII. Returns an array of
// { path, type } findings (empty if clean). `path` is a dotted/bracketed JSON
// path to help the vertical locate the offending field without us echoing the
// value. The default root path suits event properties; other callers pass
// their own field name (e.g. scanForPii(value, 'capture_context')).
function scanForPii(value, path = 'properties') {
    const findings = [];

    if (Array.isArray(value)) {
        value.forEach((item, i) => {
            findings.push(...scanForPii(item, `${path}[${i}]`));
        });
    } else if (value !== null && typeof value === 'object') {
        Object.entries(value).forEach(([key, child], i) => {
            // Scan the KEY itself, not just its value. A property *name* can carry
            // PII too - e.g. {"jane@example.com": "clicked"} would otherwise sail
            // through (we only recursed into values) and persist the raw email in
            // the JSONB column, a Bible Decision 10 violation. We report the key by
            // position, never by its text, so the error never echoes the PII - the
            // same rule we apply to values.
            const keyType = detectPiiInScalar(key);
            if (keyType) {
                findings.push({ path: `${path}[key#${i}]`, type: keyType });
            }
            // When the key itself is PII we must not propagate it into the child's
            // path either, or a nested value finding would re-leak it in the error
            // message; fall back to the positional form. Otherwise use the readable
            // dotted path.
            const childPath = keyType ? `${path}[key#${i}].value` : `${path}.${key}`;
            findings.push(...scanForPii(child, childPath));
        });
    } else {
        const type = detectPiiInScalar(value);
        if (type) {
            findings.push({ path, type });
        }
    }

    return findings;
}

// ----------------------------------------------------------------------------
// Exports
// ----------------------------------------------------------------------------

module.exports = {
    detectPiiInScalar,
    scanForPii,
};

// ============================================================================
// ThreadOS Core - JWT Signing and Verification
// ============================================================================
//
// Minimal Ed25519 JWT implementation. Only this algorithm is supported.
// Doing one thing well, instead of being a general-purpose library, lets
// us pin down exactly what we accept and refuse everything else.
//
// JWT structure: header.payload.signature, each base64url-encoded.
//   - header: { "alg": "EdDSA", "typ": "JWT", "kid": "..." }
//   - payload: { iss, sub, iat, exp, ... }
//   - signature: Ed25519 signature over "header.payload"
//
// Bible reference:
//   Decision 18: Service-to-service auth via signed JWT
// ============================================================================

const crypto = require('crypto');

// ----------------------------------------------------------------------------
// Configuration
// ----------------------------------------------------------------------------

// Tolerance for clock differences between signer and verifier. 30 seconds
// is the industry standard for service-to-service auth.
const CLOCK_SKEW_SECONDS = 30;

// Maximum allowed token lifetime. Tokens with `exp - iat` greater than this
// are rejected, regardless of clock skew. Service-to-service tokens don't
// need to be long-lived; this prevents pathologically long-lived tokens
// from being valid forever if a private key is compromised.
const MAX_TOKEN_LIFETIME_SECONDS = 24 * 60 * 60;  // 24 hours

// ----------------------------------------------------------------------------
// Error classes
// ----------------------------------------------------------------------------
//
// Named errors let route handlers respond appropriately to different failure
// modes (e.g., expired token vs forged signature).
// ----------------------------------------------------------------------------

class JwtMalformedError extends Error {
    constructor(message) {
        super(message);
        this.name = 'JwtMalformedError';
        this.code = 'jwt_malformed';
    }
}

class JwtSignatureError extends Error {
    constructor(message) {
        super(message);
        this.name = 'JwtSignatureError';
        this.code = 'jwt_invalid_signature';
    }
}

class JwtExpiredError extends Error {
    constructor(message) {
        super(message);
        this.name = 'JwtExpiredError';
        this.code = 'jwt_expired';
    }
}

class JwtClaimError extends Error {
    constructor(message) {
        super(message);
        this.name = 'JwtClaimError';
        this.code = 'jwt_claim_invalid';
    }
}

// ----------------------------------------------------------------------------
// Base64url encoding helpers
// ----------------------------------------------------------------------------
//
// JWT uses base64url (RFC 4648 §5) which is base64 with three substitutions:
//   - '+' becomes '-'
//   - '/' becomes '_'
//   - trailing '=' padding removed
//
// Node's Buffer supports this natively as 'base64url' encoding.
// ----------------------------------------------------------------------------

function base64urlEncode(buffer) {
    return buffer.toString('base64url');
}

function base64urlDecode(str) {
    return Buffer.from(str, 'base64url');
}

function base64urlEncodeJson(obj) {
    return base64urlEncode(Buffer.from(JSON.stringify(obj), 'utf8'));
}

function base64urlDecodeJson(str) {
    const buf = base64urlDecode(str);
    return JSON.parse(buf.toString('utf8'));
}

// ----------------------------------------------------------------------------
// Sign a token
// ----------------------------------------------------------------------------
//
// claims: { iss, sub, iat, exp, ... }
//   - iss (issuer): required, identifies which vertical signed this
//   - sub (subject): required, the tenant_id this token authorizes
//   - iat (issued-at): optional, defaults to now
//   - exp (expiry): optional, defaults to iat + 1 hour
//   - any other claims: passed through unchanged
//
// privateKeyPem: Ed25519 private key in PEM format
// kid: key ID, included in header so verifier can pick the right key
//
// Returns: signed JWT string in standard header.payload.signature form
// ----------------------------------------------------------------------------

function signToken(claims, privateKeyPem, kid) {
    if (!claims || typeof claims !== 'object') {
        throw new Error('claims must be an object');
    }
    if (!privateKeyPem) {
        throw new Error('privateKeyPem is required');
    }
    if (!kid) {
        throw new Error('kid is required');
    }

    // Validate the private key is Ed25519
    let keyObject;
    try {
        keyObject = crypto.createPrivateKey(privateKeyPem);
    } catch (err) {
        throw new Error(`Invalid private key: ${err.message}`);
    }
    if (keyObject.asymmetricKeyType !== 'ed25519') {
        throw new Error(
            `Expected Ed25519 private key, got ${keyObject.asymmetricKeyType}`
        );
    }

    // Build the payload with defaults
    const now = Math.floor(Date.now() / 1000);
    const payload = {
        iat: now,
        exp: now + 3600,    // 1 hour default
        ...claims,           // caller overrides take precedence
    };

    if (!payload.iss) {
        throw new Error('iss claim is required');
    }
    if (!payload.sub) {
        throw new Error('sub claim is required');
    }

    // Build the header
    const header = {
        alg: 'EdDSA',
        typ: 'JWT',
        kid,
    };

    // Encode and sign
    const headerB64 = base64urlEncodeJson(header);
    const payloadB64 = base64urlEncodeJson(payload);
    const signingInput = `${headerB64}.${payloadB64}`;

    const signature = crypto.sign(null, Buffer.from(signingInput, 'utf8'), keyObject);
    const signatureB64 = base64urlEncode(signature);

    return `${signingInput}.${signatureB64}`;
}

// ----------------------------------------------------------------------------
// Verify a token
// ----------------------------------------------------------------------------
//
// token: the JWT string
// publicKeyOrJwk: an Ed25519 public key (either PEM string or JWK object)
//
// Returns the verified claims object on success.
//
// Throws:
//   - JwtMalformedError: token structure is wrong, bad base64, bad JSON,
//     wrong number of parts, etc.
//   - JwtSignatureError: signature doesn't verify
//   - JwtExpiredError: token is past its exp (with skew allowance)
//   - JwtClaimError: required claim missing or invalid (including iat
//     in the future, lifetime too long, missing iss/sub)
// ----------------------------------------------------------------------------

function verifyToken(token, publicKeyOrJwk) {
    if (typeof token !== 'string') {
        throw new JwtMalformedError('token must be a string');
    }

    const parts = token.split('.');
    if (parts.length !== 3) {
        throw new JwtMalformedError(
            `expected 3 dot-separated parts, got ${parts.length}`
        );
    }

    const [headerB64, payloadB64, signatureB64] = parts;

    // Decode header
    let header;
    try {
        header = base64urlDecodeJson(headerB64);
    } catch (err) {
        throw new JwtMalformedError(`header is not valid base64-encoded JSON: ${err.message}`);
    }

    // PIN ALGORITHM: only EdDSA is accepted. This blocks the famous
    // alg=none and alg-confusion vulnerability classes.
    if (header.alg !== 'EdDSA') {
        throw new JwtMalformedError(
            `unsupported algorithm: expected EdDSA, got ${header.alg}`
        );
    }

    if (header.typ !== 'JWT') {
        throw new JwtMalformedError(
            `unsupported type: expected JWT, got ${header.typ}`
        );
    }

    if (!header.kid) {
        throw new JwtMalformedError('header missing kid');
    }

    // Decode payload
    let payload;
    try {
        payload = base64urlDecodeJson(payloadB64);
    } catch (err) {
        throw new JwtMalformedError(`payload is not valid base64-encoded JSON: ${err.message}`);
    }

    // Decode signature
    let signature;
    try {
        signature = base64urlDecode(signatureB64);
    } catch (err) {
        throw new JwtMalformedError(`signature is not valid base64: ${err.message}`);
    }

    // Build the public key from PEM or JWK
    let publicKeyObject;
    try {
        if (typeof publicKeyOrJwk === 'string') {
            publicKeyObject = crypto.createPublicKey(publicKeyOrJwk);
        } else if (publicKeyOrJwk && typeof publicKeyOrJwk === 'object') {
            publicKeyObject = crypto.createPublicKey({ key: publicKeyOrJwk, format: 'jwk' });
        } else {
            throw new Error('publicKeyOrJwk must be a PEM string or JWK object');
        }
    } catch (err) {
        throw new Error(`Invalid public key: ${err.message}`);
    }

    if (publicKeyObject.asymmetricKeyType !== 'ed25519') {
        throw new Error(
            `Expected Ed25519 public key, got ${publicKeyObject.asymmetricKeyType}`
        );
    }

    // Verify the signature
    const signingInput = `${headerB64}.${payloadB64}`;
    const signatureValid = crypto.verify(
        null,
        Buffer.from(signingInput, 'utf8'),
        publicKeyObject,
        signature
    );

    if (!signatureValid) {
        throw new JwtSignatureError('signature verification failed');
    }

    // Validate required claims
    if (!payload.iss || typeof payload.iss !== 'string') {
        throw new JwtClaimError('iss claim missing or not a string');
    }
    if (!payload.sub || typeof payload.sub !== 'string') {
        throw new JwtClaimError('sub claim missing or not a string');
    }
    if (typeof payload.iat !== 'number') {
        throw new JwtClaimError('iat claim missing or not a number');
    }
    if (typeof payload.exp !== 'number') {
        throw new JwtClaimError('exp claim missing or not a number');
    }

    // Validate timing
    const now = Math.floor(Date.now() / 1000);

    if (payload.iat > now + CLOCK_SKEW_SECONDS) {
        throw new JwtClaimError(
            `iat (${payload.iat}) is in the future relative to now (${now})`
        );
    }

    if (now > payload.exp + CLOCK_SKEW_SECONDS) {
        throw new JwtExpiredError(
            `token expired at ${payload.exp}, now is ${now}`
        );
    }

    if (payload.exp - payload.iat > MAX_TOKEN_LIFETIME_SECONDS) {
        throw new JwtClaimError(
            `token lifetime ${payload.exp - payload.iat}s exceeds maximum ${MAX_TOKEN_LIFETIME_SECONDS}s`
        );
    }

    return payload;
}

// ----------------------------------------------------------------------------
// Decode without verifying
// ----------------------------------------------------------------------------
//
// Returns the parsed header and payload of a token WITHOUT verifying the
// signature or checking expiry. Useful for:
//   - Looking up the kid before fetching the key
//   - Debugging
//
// NEVER use the returned data as if it were trusted - the token might be
// forged. Always follow with verifyToken().
// ----------------------------------------------------------------------------

function decodeUnverified(token) {
    if (typeof token !== 'string') {
        throw new JwtMalformedError('token must be a string');
    }
    const parts = token.split('.');
    if (parts.length !== 3) {
        throw new JwtMalformedError(
            `expected 3 dot-separated parts, got ${parts.length}`
        );
    }
    try {
        return {
            header: base64urlDecodeJson(parts[0]),
            payload: base64urlDecodeJson(parts[1]),
        };
    } catch (err) {
        throw new JwtMalformedError(`failed to decode token: ${err.message}`);
    }
}

// ----------------------------------------------------------------------------
// Exports
// ----------------------------------------------------------------------------

module.exports = {
    signToken,
    verifyToken,
    decodeUnverified,
    JwtMalformedError,
    JwtSignatureError,
    JwtExpiredError,
    JwtClaimError,
    // Constants exposed for testing
    CLOCK_SKEW_SECONDS,
    MAX_TOKEN_LIFETIME_SECONDS,
};
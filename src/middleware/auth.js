// ============================================================================
// ThreadOS Core - Auth Middleware
// ============================================================================
//
// requireSignedRequest: Express middleware that requires a valid signed JWT
// in the Authorization header. On success, attaches verified context to req:
//   - req.tenantId: the tenant_id from the JWT's sub claim
//   - req.verticalSlug: the vertical that signed (from iss claim)
//   - req.tokenClaims: the full verified payload
//
// On failure, returns a structured 401 (client-side problems) or 503 (server
// can't verify because of infrastructure issue like JWKS fetch failure).
//
// Pipeline:
//   1. Extract Authorization: Bearer <token>
//   2. Decode the token WITHOUT verifying to read iss and kid
//   3. Look up registered vertical by iss in database (cached)
//   4. Fetch the vertical's JWKS document (cached per Session 2)
//   5. Find the public key matching kid
//   6. Verify token signature + claims + timing (per Session 3)
//   7. Attach verified context to req, call next()
//
// Bible references:
//   Decision 18: Service-to-service auth via signed JWT
//   Decision 7: Gatekeeper - actionable structured errors
// ============================================================================

const {
    verifyToken,
    decodeUnverified,
    JwtMalformedError,
    JwtSignatureError,
    JwtExpiredError,
    JwtClaimError,
} = require('../lib/jwt');
const { getJwksForVertical, findKeyByKid } = require('../lib/jwks');
const { query } = require('../lib/db');

// ----------------------------------------------------------------------------
// Vertical lookup cache
// ----------------------------------------------------------------------------
//
// Avoid a database round-trip on every authenticated request. Verticals
// change rarely; a few minutes of staleness is acceptable.
//
// Cache structure: { [slug]: { vertical, cachedAt } }
//
// TODO (tracked): distributed cache when scaling out. Current per-instance
// cache means each Core instance independently fetches; key revocation
// requires all caches to expire.
// ----------------------------------------------------------------------------

const VERTICAL_CACHE_TTL_MS = 5 * 60 * 1000;  // 5 minutes
const _verticalCache = new Map();

function _isCacheEntryValid(entry) {
    if (!entry) return false;
    return (Date.now() - entry.cachedAt) < VERTICAL_CACHE_TTL_MS;
}

async function lookupVertical(slug) {
    const cached = _verticalCache.get(slug);
    if (_isCacheEntryValid(cached)) {
        return cached.vertical;
    }

    const result = await query(
        `SELECT id, slug, display_name, jwks_url, jwks_cache_ttl_seconds, is_active
         FROM registered_verticals
         WHERE slug = $1 AND is_active = true
         LIMIT 1`,
        [slug]
    );

    const vertical = result.rows[0] || null;
    _verticalCache.set(slug, { vertical, cachedAt: Date.now() });
    return vertical;
}

function _resetVerticalCache() {
    _verticalCache.clear();
}

// ----------------------------------------------------------------------------
// Error response helpers
// ----------------------------------------------------------------------------

function authError(res, code, message) {
    return res.status(401).json({
        error: {
            code,
            message,
        },
    });
}

function serviceUnavailable(res, message) {
    return res.status(503).json({
        error: {
            code: 'service_unavailable',
            message,
        },
    });
}

// ----------------------------------------------------------------------------
// The middleware itself
// ----------------------------------------------------------------------------

async function requireSignedRequest(req, res, next) {
    // 1. Extract Authorization header
    const authHeader = req.header('Authorization');
    if (!authHeader) {
        return authError(res, 'missing_auth', 'Authorization header is required');
    }

    const match = authHeader.match(/^Bearer\s+(.+)$/);
    if (!match) {
        return authError(res, 'invalid_auth_format', 'Authorization header must be: Bearer <token>');
    }
    const token = match[1].trim();

    if (!token) {
        return authError(res, 'invalid_auth_format', 'Authorization Bearer token is empty');
    }

    // 2. Decode unverified to read iss and kid
    let unverified;
    try {
        unverified = decodeUnverified(token);
    } catch (err) {
        return authError(res, 'token_malformed', `token is malformed: ${err.message}`);
    }

    const iss = unverified.payload && unverified.payload.iss;
    const kid = unverified.header && unverified.header.kid;

    if (!iss) {
        return authError(res, 'token_malformed', 'token missing iss claim');
    }
    if (!kid) {
        return authError(res, 'token_malformed', 'token missing kid in header');
    }

    // 3. Look up registered vertical
    let vertical;
    try {
        vertical = await lookupVertical(iss);
    } catch (err) {
        // Database error - treat as infrastructure issue
        console.error('Vertical lookup failed:', err.message);
        return serviceUnavailable(res, 'unable to verify request at this time');
    }

    if (!vertical) {
        return authError(
            res,
            'unknown_issuer',
            `issuer "${iss}" is not a registered vertical`
        );
    }

    // 4. Fetch the vertical's JWKS
    let jwks;
    try {
        jwks = await getJwksForVertical(vertical.jwks_url, vertical.jwks_cache_ttl_seconds);
    } catch (err) {
        // JWKS fetch failure - infrastructure issue on vertical or network side
        console.error(`JWKS fetch failed for ${iss}:`, err.message);
        return serviceUnavailable(res, 'unable to verify request at this time');
    }

    // 5. Find the public key matching kid
    const jwk = findKeyByKid(jwks, kid);
    if (!jwk) {
        return authError(
            res,
            'unknown_key',
            `key id "${kid}" not found in issuer's JWKS`
        );
    }

    // 6. Verify the token (signature, claims, timing)
    let verifiedClaims;
    try {
        verifiedClaims = verifyToken(token, jwk);
    } catch (err) {
        if (err instanceof JwtSignatureError) {
            return authError(res, 'invalid_signature', 'token signature verification failed');
        }
        if (err instanceof JwtExpiredError) {
            return authError(res, 'token_expired', 'token has expired');
        }
        if (err instanceof JwtClaimError) {
            return authError(res, 'invalid_claims', err.message);
        }
        if (err instanceof JwtMalformedError) {
            return authError(res, 'token_malformed', err.message);
        }
        // Unexpected error - log and treat as service unavailable
        console.error('Unexpected JWT verification error:', err);
        return serviceUnavailable(res, 'unable to verify request at this time');
    }

    // 7. Attach verified context and continue
    req.tokenClaims = verifiedClaims;
    req.tenantId = verifiedClaims.sub;
    req.verticalSlug = verifiedClaims.iss;

    next();
}

// ----------------------------------------------------------------------------
// Exports
// ----------------------------------------------------------------------------

module.exports = {
    requireSignedRequest,
    lookupVertical,
    // Internal: testing
    _resetVerticalCache,
};
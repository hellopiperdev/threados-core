// ============================================================================
// ThreadOS Core - Test Auth Helper
// ============================================================================
//
// Shared scaffolding for tests that need authenticated requests. Encapsulates:
//   - Generating an Ed25519 keypair for a test vertical
//   - Spinning up a local JWKS HTTP server that serves the vertical's public
//     key
//   - Registering the test vertical in the database (registered_verticals)
//   - Signing JWT tokens for arbitrary tenants
//   - Tearing it all down cleanly
//
// Usage pattern in a test file:
//
//   const authHelper = require('../helpers/auth');
//
//   let authCtx;
//
//   async function setup() {
//       authCtx = await authHelper.setupTestVertical();
//       // ... rest of test setup
//   }
//
//   async function teardown() {
//       await authHelper.teardownTestVertical(authCtx);
//       // ... rest of test teardown
//   }
//
//   // In a test:
//   const token = authHelper.signTestToken(authCtx, { sub: tenantId });
//   await request({
//       method: 'POST',
//       headers: { 'Authorization': `Bearer ${token}` },
//       ...
//   });
// ============================================================================

const crypto = require('crypto');
const http = require('http');
const {
    pemPublicKeyToJwk,
    computeKid,
    _resetVerticalJwksCache,
} = require('../../src/lib/jwks');
const { signToken } = require('../../src/lib/jwt');
const { query } = require('../../src/lib/db');
const { _resetVerticalCache } = require('../../src/middleware/auth');

// ----------------------------------------------------------------------------
// Port allocation
// ----------------------------------------------------------------------------
//
// Each test file that uses this helper picks a unique port range for its
// JWKS server. We default to a port chosen by the OS (passing 0) so multiple
// test files can run sequentially without collisions.
// ----------------------------------------------------------------------------

function _startJwksServer(jwksDocument) {
    return new Promise((resolve) => {
        const server = http.createServer((req, res) => {
            if (req.url === '/jwks.json') {
                res.statusCode = 200;
                res.setHeader('Content-Type', 'application/json');
                res.end(JSON.stringify(jwksDocument));
            } else {
                res.statusCode = 404;
                res.end('not found');
            }
        });

        server.listen(0, () => {
            const port = server.address().port;
            resolve({ server, port });
        });
    });
}

// ----------------------------------------------------------------------------
// setupTestVertical
// ----------------------------------------------------------------------------
//
// Creates a test vertical with a fresh keypair, a local JWKS server, and a
// database registration pointing Core at that server. Returns a context
// object that test code passes to signTestToken() and teardownTestVertical().
//
// Options:
//   slug: vertical slug (default: `test-vertical-<random>`)
//   jwksCacheTtlSeconds: TTL for Core's JWKS cache (default: 0 = no cache,
//     useful in tests so we don't have to wait for cache expiry)
// ----------------------------------------------------------------------------

async function setupTestVertical(options = {}) {
    // Generate keypair
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    const kid = computeKid(publicKey);
    const jwk = pemPublicKeyToJwk(publicKey, kid);
    const jwksDocument = { keys: [jwk] };

    // Start local JWKS server
    const { server: jwksServer, port } = await _startJwksServer(jwksDocument);
    const jwksUrl = `http://localhost:${port}/jwks.json`;

    // Slug. Random suffix prevents conflicts across test files run in parallel
    // or back-to-back.
    const randomSuffix = crypto.randomBytes(4).toString('hex');
    const slug = options.slug || `test-vertical-${randomSuffix}`;

    // Default to 0 TTL so tests don't see stale-cache surprises. Tests that
    // specifically want to verify caching behavior can override.
    const jwksCacheTtlSeconds = options.jwksCacheTtlSeconds !== undefined
        ? options.jwksCacheTtlSeconds
        : 0;

    // Clear any cached state from previous tests
    _resetVerticalJwksCache();
    _resetVerticalCache();

    // Register in database
    const result = await query(
        `INSERT INTO registered_verticals
         (slug, display_name, jwks_url, jwks_cache_ttl_seconds, is_active)
         VALUES ($1, $2, $3, $4, true)
         RETURNING id`,
        [slug, `Test Vertical (${slug})`, jwksUrl, jwksCacheTtlSeconds]
    );

    return {
        slug,
        verticalId: result.rows[0].id,
        privateKey,
        publicKey,
        kid,
        jwksUrl,
        jwksServer,
    };
}

// ----------------------------------------------------------------------------
// signTestToken
// ----------------------------------------------------------------------------
//
// Signs a JWT using the test vertical's private key. Defaults to valid
// claims; overrides let tests construct specific failure scenarios.
//
// Common overrides:
//   sub: the tenant_id (required)
//   iss: override issuer (used to test unknown-issuer paths)
//   iat: override issued-at
//   exp: override expiry
// ----------------------------------------------------------------------------

function signTestToken(authCtx, claimOverrides = {}) {
    const now = Math.floor(Date.now() / 1000);
    const claims = {
        iss: authCtx.slug,
        iat: now,
        exp: now + 3600,
        ...claimOverrides,
    };

    if (!claims.sub) {
        throw new Error('signTestToken: claims.sub is required (the tenant_id)');
    }

    return signToken(claims, authCtx.privateKey, authCtx.kid);
}

// ----------------------------------------------------------------------------
// teardownTestVertical
// ----------------------------------------------------------------------------
//
// Cleans up everything created by setupTestVertical: closes the JWKS HTTP
// server, deletes the database row, clears caches.
//
// Safe to call multiple times; idempotent.
// ----------------------------------------------------------------------------

async function teardownTestVertical(authCtx) {
    if (!authCtx) return;

    // Close JWKS server
    if (authCtx.jwksServer) {
        await new Promise((resolve) => authCtx.jwksServer.close(resolve));
    }

    // Delete database row
    if (authCtx.slug) {
        try {
            await query(
                `DELETE FROM registered_verticals WHERE slug = $1`,
                [authCtx.slug]
            );
        } catch (err) {
            console.error(`Failed to delete test vertical ${authCtx.slug}:`, err.message);
        }
    }

    // Clear caches so subsequent tests don't see stale state
    _resetVerticalJwksCache();
    _resetVerticalCache();
}

// ----------------------------------------------------------------------------
// Exports
// ----------------------------------------------------------------------------

module.exports = {
    setupTestVertical,
    signTestToken,
    teardownTestVertical,
};
// ============================================================================
// ThreadOS Core - Auth Middleware Tests
// ============================================================================
//
// Tests requireSignedRequest in isolation. We invoke the middleware directly
// with mocked req/res objects rather than through an HTTP server, so we can
// verify the precise response shape for each failure mode.
//
// This is the security-critical surface of Step 5. Every test verifies a
// specific property that, if regressed, would represent a real vulnerability.
//
// Usage:
//   node tests/middleware/auth.test.js
// ============================================================================

require('dotenv').config();

const crypto = require('crypto');
const authHelper = require('../helpers/auth');
const { requireSignedRequest } = require('../../src/middleware/auth');
const { signToken } = require('../../src/lib/jwt');
const { computeKid } = require('../../src/lib/jwks');
const { shutdown } = require('../../src/lib/db');

// ----------------------------------------------------------------------------
// Test runner state
// ----------------------------------------------------------------------------

let passed = 0;
let failed = 0;

const colors = {
    reset: '\x1b[0m',
    bold: '\x1b[1m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    red: '\x1b[31m',
    blue: '\x1b[34m',
    gray: '\x1b[90m',
};

function section(name) {
    console.log(`\n${colors.bold}${colors.blue}━━ ${name} ━━${colors.reset}`);
}

function test(name, actual, expected) {
    const matches = JSON.stringify(actual) === JSON.stringify(expected);
    if (matches) {
        passed++;
        console.log(`${colors.green}✓${colors.reset} ${name}`);
    } else {
        failed++;
        console.log(`${colors.red}✗${colors.reset} ${name}`);
        console.log(`  ${colors.gray}expected:${colors.reset} ${JSON.stringify(expected)}`);
        console.log(`  ${colors.gray}actual:  ${colors.reset} ${JSON.stringify(actual)}`);
    }
}

function testThat(name, condition, hint) {
    if (condition) {
        passed++;
        console.log(`${colors.green}✓${colors.reset} ${name}`);
    } else {
        failed++;
        console.log(`${colors.red}✗${colors.reset} ${name}`);
        if (hint) console.log(`  ${colors.gray}${hint}${colors.reset}`);
    }
}

// ----------------------------------------------------------------------------
// Mock req/res factory
// ----------------------------------------------------------------------------
//
// Builds a minimal stub of Express's req/res objects sufficient for the
// middleware to operate on. Captures status code and JSON body so tests
// can assert on them.
// ----------------------------------------------------------------------------

function buildReq(authHeader) {
    return {
        headers: authHeader !== undefined
            ? { authorization: authHeader }
            : {},
        header(name) {
            return this.headers[name.toLowerCase()];
        },
    };
}

function buildRes() {
    const res = {
        statusCode: null,
        body: null,
        ended: false,
    };
    res.status = function (code) {
        this.statusCode = code;
        return this;
    };
    res.json = function (payload) {
        this.body = payload;
        this.ended = true;
        return this;
    };
    return res;
}

async function runMiddleware(authHeader) {
    const req = buildReq(authHeader);
    const res = buildRes();
    let nextCalled = false;
    let nextError = null;

    await requireSignedRequest(req, res, (err) => {
        nextCalled = true;
        nextError = err;
    });

    return { req, res, nextCalled, nextError };
}

// ----------------------------------------------------------------------------
// Setup / teardown
// ----------------------------------------------------------------------------

let authCtx = null;
let testTenantId = null;

async function setup() {
    // Create a test tenant we can reference via sub claim
    const tenantResult = await require('../../src/lib/db').query(
        `INSERT INTO tenants (slug, display_name, vertical_module)
         VALUES ($1, 'Auth Middleware Test', 'test')
         RETURNING id`,
        [`_test_auth_middleware_${Date.now()}`]
    );
    testTenantId = tenantResult.rows[0].id;

    // Set up auth context (vertical + JWKS server + DB registration)
    authCtx = await authHelper.setupTestVertical();
}

async function teardown() {
    if (authCtx) {
        await authHelper.teardownTestVertical(authCtx);
    }
    if (testTenantId) {
        try {
            await require('../../src/lib/db').query(
                `DELETE FROM tenants WHERE id = $1`,
                [testTenantId]
            );
        } catch (err) {
            // best effort
        }
    }
    await shutdown();
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

async function runTests() {
    console.log(`${colors.bold}ThreadOS Core - Auth Middleware Tests${colors.reset}`);

    try {
        section('Setup');
        await setup();
        console.log(`${colors.green}✓${colors.reset} Test vertical registered: ${authCtx.slug}`);
        console.log(`${colors.green}✓${colors.reset} Test tenant created: ${testTenantId}`);

        // --------------------------------------------------------------------
        // Happy path
        // --------------------------------------------------------------------

        section('Happy path');

        const validToken = authHelper.signTestToken(authCtx, { sub: testTenantId });
        const { req, res, nextCalled, nextError } = await runMiddleware(`Bearer ${validToken}`);

        test('next() is called', nextCalled, true);
        testThat('next() called without error', nextError === null || nextError === undefined);
        test('no response written', res.ended, false);
        test('req.tenantId is set', req.tenantId, testTenantId);
        test('req.verticalSlug is set', req.verticalSlug, authCtx.slug);
        testThat('req.tokenClaims contains iss', req.tokenClaims && req.tokenClaims.iss === authCtx.slug);

        // --------------------------------------------------------------------
        // Missing or malformed Authorization header
        // --------------------------------------------------------------------

        section('Missing or malformed Authorization header');

        let r = await runMiddleware(undefined);
        test('missing header returns 401', r.res.statusCode, 401);
        test('missing header error code', r.res.body.error.code, 'missing_auth');

        r = await runMiddleware('');
        test('empty header returns 401', r.res.statusCode, 401);
        test('empty header error code', r.res.body.error.code, 'missing_auth');

        r = await runMiddleware(`Basic abc123`);
        test('non-Bearer scheme returns 401', r.res.statusCode, 401);
        test('non-Bearer error code', r.res.body.error.code, 'invalid_auth_format');

        r = await runMiddleware(`Bearer`);
        test('Bearer with no token returns 401', r.res.statusCode, 401);
        test('Bearer-without-token error code', r.res.body.error.code, 'invalid_auth_format');

        r = await runMiddleware(`Bearer   `);
        test('Bearer with whitespace-only token returns 401', r.res.statusCode, 401);

        // --------------------------------------------------------------------
        // Malformed tokens
        // --------------------------------------------------------------------

        section('Malformed tokens');

        r = await runMiddleware('Bearer notarealtoken');
        test('malformed token returns 401', r.res.statusCode, 401);
        test('malformed token error code', r.res.body.error.code, 'token_malformed');

        r = await runMiddleware('Bearer one.two');
        test('two-part token returns 401', r.res.statusCode, 401);
        test('two-part token error code', r.res.body.error.code, 'token_malformed');

        // Token with no iss claim
        const noIssToken = (() => {
            const header = { alg: 'EdDSA', typ: 'JWT', kid: authCtx.kid };
            const payload = { sub: testTenantId, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 3600 };
            const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
            const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
            const signingInput = `${headerB64}.${payloadB64}`;
            const keyObject = crypto.createPrivateKey(authCtx.privateKey);
            const signature = crypto.sign(null, Buffer.from(signingInput, 'utf8'), keyObject);
            return `${signingInput}.${signature.toString('base64url')}`;
        })();
        r = await runMiddleware(`Bearer ${noIssToken}`);
        test('token without iss returns 401', r.res.statusCode, 401);
        test('missing iss error code', r.res.body.error.code, 'token_malformed');

        // Token with no kid in header
        const noKidToken = (() => {
            const header = { alg: 'EdDSA', typ: 'JWT' };  // no kid
            const payload = { iss: authCtx.slug, sub: testTenantId, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 3600 };
            const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
            const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
            return `${headerB64}.${payloadB64}.fake`;
        })();
        r = await runMiddleware(`Bearer ${noKidToken}`);
        test('token without kid returns 401', r.res.statusCode, 401);
        test('missing kid error code', r.res.body.error.code, 'token_malformed');

        // --------------------------------------------------------------------
        // Unknown issuer
        // --------------------------------------------------------------------

        section('Unknown issuer');

        const unknownIssToken = authHelper.signTestToken(authCtx, {
            sub: testTenantId,
            iss: 'unregistered-vertical-xyz',
        });
        r = await runMiddleware(`Bearer ${unknownIssToken}`);
        test('unknown issuer returns 401', r.res.statusCode, 401);
        test('unknown issuer error code', r.res.body.error.code, 'unknown_issuer');

        // --------------------------------------------------------------------
        // Unknown key id
        // --------------------------------------------------------------------

        section('Unknown key id');

        // Sign with a freshly generated key whose kid won't match the JWKS
        const { privateKey: otherPrivate, publicKey: otherPublic } = crypto.generateKeyPairSync('ed25519', {
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        });
        const otherKid = computeKid(otherPublic);
        const wrongKidToken = signToken(
            { iss: authCtx.slug, sub: testTenantId, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 3600 },
            otherPrivate,
            otherKid
        );
        r = await runMiddleware(`Bearer ${wrongKidToken}`);
        test('unknown kid returns 401', r.res.statusCode, 401);
        test('unknown kid error code', r.res.body.error.code, 'unknown_key');

        // --------------------------------------------------------------------
        // Invalid signature
        // --------------------------------------------------------------------

        section('Invalid signature');

        // Sign a token, then tamper with the payload
        const goodToken = authHelper.signTestToken(authCtx, { sub: testTenantId });
        const parts = goodToken.split('.');
        const tamperedPayload = Buffer.from(JSON.stringify({
            iss: authCtx.slug,
            sub: '99999999-9999-9999-9999-999999999999',
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + 3600,
        })).toString('base64url');
        const tamperedToken = `${parts[0]}.${tamperedPayload}.${parts[2]}`;
        r = await runMiddleware(`Bearer ${tamperedToken}`);
        test('tampered payload returns 401', r.res.statusCode, 401);
        test('tampered payload error code', r.res.body.error.code, 'invalid_signature');

        // --------------------------------------------------------------------
        // Expired token
        // --------------------------------------------------------------------

        section('Expired token');

        const now = Math.floor(Date.now() / 1000);
        const expiredToken = authHelper.signTestToken(authCtx, {
            sub: testTenantId,
            iat: now - 7200,
            exp: now - 3600,
        });
        r = await runMiddleware(`Bearer ${expiredToken}`);
        test('expired token returns 401', r.res.statusCode, 401);
        test('expired token error code', r.res.body.error.code, 'token_expired');

        // --------------------------------------------------------------------
        // Algorithm confusion attack (the famous vulnerability)
        // --------------------------------------------------------------------

        section('Algorithm confusion attack');

        // Forge a token claiming alg=none with the right kid
        const noneHeader = Buffer.from(JSON.stringify({
            alg: 'none',
            typ: 'JWT',
            kid: authCtx.kid,
        })).toString('base64url');
        const validPayloadStr = Buffer.from(JSON.stringify({
            iss: authCtx.slug,
            sub: testTenantId,
            iat: now,
            exp: now + 3600,
        })).toString('base64url');
        const noneToken = `${noneHeader}.${validPayloadStr}.`;
        r = await runMiddleware(`Bearer ${noneToken}`);
        test('alg=none attack returns 401', r.res.statusCode, 401);
        testThat('alg=none rejected via malformed code',
            r.res.body.error.code === 'token_malformed');

    } finally {
        section('Teardown');
        try {
            await teardown();
            console.log(`${colors.green}✓${colors.reset} Resources cleaned up`);
        } catch (err) {
            console.log(`${colors.yellow}⚠${colors.reset} Teardown error: ${err.message}`);
        }
    }

    // ------------------------------------------------------------------------
    // Summary
    // ------------------------------------------------------------------------

    console.log(`\n${colors.bold}━━ Summary ━━${colors.reset}`);
    console.log(`${colors.green}Passed:${colors.reset} ${passed}`);
    if (failed > 0) {
        console.log(`${colors.red}Failed:${colors.reset} ${failed}`);
        process.exit(1);
    } else {
        console.log(`${colors.gray}No failures.${colors.reset}\n`);
        process.exit(0);
    }
}

runTests().catch(err => {
    console.error('Unexpected error in test runner:', err);
    process.exit(1);
});
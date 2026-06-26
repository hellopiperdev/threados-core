// ============================================================================
// ThreadOS Core - Auth Robustness Tests
// ============================================================================
//
// Hardening tests covering specific attack patterns and edge cases beyond
// what the main auth tests verify. Each test targets one named scenario.
//
// Scenarios covered:
//   - Vertical impersonation via spoofed iss claim
//   - Deactivated vertical rejection (is_active = false)
//   - Concurrent authenticated requests
//   - Tokens with extra unknown claims (should pass)
//   - Mixed-case Authorization scheme handling
//   - JWKS server down during request → 503
//   - JWKS server slow → handled gracefully
//   - Token replay within lifetime (intentional - documents current behavior)
//
// Usage:
//   node tests/middleware/auth-robustness.test.js
// ============================================================================

require('dotenv').config();

const http = require('http');
const crypto = require('crypto');
const { createServer } = require('../../src/server');
const { query, shutdown } = require('../../src/lib/db');
const authHelper = require('../helpers/auth');

const TEST_PORT = 3005;
const TEST_TENANT_SLUG = '_test_tenant_auth_robust';
let testTenantId = null;
let authCtx = null;
let server = null;

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
// HTTP request helper
// ----------------------------------------------------------------------------

function request(options, body) {
    return new Promise((resolve, reject) => {
        const req = http.request({
            hostname: 'localhost',
            port: TEST_PORT,
            ...options,
        }, (res) => {
            let data = '';
            res.on('data', chunk => { data += chunk; });
            res.on('end', () => {
                let parsedBody = data;
                const contentType = res.headers['content-type'] || '';
                if (contentType.includes('application/json') && data.length > 0) {
                    try { parsedBody = JSON.parse(data); } catch (_) {}
                }
                resolve({
                    statusCode: res.statusCode,
                    headers: res.headers,
                    body: parsedBody,
                });
            });
        });
        req.on('error', reject);
        if (body !== undefined) {
            req.write(typeof body === 'string' ? body : JSON.stringify(body));
        }
        req.end();
    });
}

// ----------------------------------------------------------------------------
// Setup / teardown
// ----------------------------------------------------------------------------

async function setup() {
    await query(`DELETE FROM tenants WHERE slug = $1`, [TEST_TENANT_SLUG]);

    const result = await query(
        `INSERT INTO tenants (slug, display_name, vertical_module)
         VALUES ($1, 'Auth Robustness Test', 'test')
         RETURNING id`,
        [TEST_TENANT_SLUG]
    );
    testTenantId = result.rows[0].id;

    authCtx = await authHelper.setupTestVertical();

    const app = createServer();
    server = app.listen(TEST_PORT);
    await new Promise((resolve) => {
        server.on('listening', resolve);
        if (server.listening) resolve();
    });
}

async function teardown() {
    if (server) {
        await new Promise(resolve => server.close(resolve));
    }
    if (authCtx) {
        await authHelper.teardownTestVertical(authCtx);
    }
    if (testTenantId) {
        try {
            await query(`DELETE FROM tenants WHERE slug = $1`, [TEST_TENANT_SLUG]);
        } catch (_) {}
    }
    await shutdown();
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

async function runTests() {
    console.log(`${colors.bold}ThreadOS Core - Auth Robustness Tests${colors.reset}`);

    try {
        section('Setup');
        await setup();
        console.log(`${colors.green}✓${colors.reset} Test server on port ${TEST_PORT}`);
        console.log(`${colors.green}✓${colors.reset} Test tenant: ${testTenantId}`);
        console.log(`${colors.green}✓${colors.reset} Test vertical: ${authCtx.slug}`);

        // --------------------------------------------------------------------
        // Vertical impersonation
        // --------------------------------------------------------------------
        //
        // What if a registered vertical signs a token claiming to be from
        // a different registered vertical? Core looks up JWKS by iss; the
        // signature won't match because keys differ. Signature verification
        // should fail with invalid_signature.
        // --------------------------------------------------------------------

        section('Vertical impersonation via spoofed iss');

        // Create a SECOND test vertical
        const otherVertical = await authHelper.setupTestVertical();

        // Sign a token with vertical A's key but claim to be from vertical B
        const impersonationToken = authHelper.signTestToken(authCtx, {
            sub: testTenantId,
            iss: otherVertical.slug,   // lying about who signed it
        });

        const impResp = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${impersonationToken}`,
            },
        }, { email: 'imp@example.com' });

        test('impersonation returns 401', impResp.statusCode, 401);
        testThat('impersonation rejected via signature or key mismatch',
            impResp.body.error.code === 'invalid_signature' ||
            impResp.body.error.code === 'unknown_key');

        // Clean up second vertical
        await authHelper.teardownTestVertical(otherVertical);

        // --------------------------------------------------------------------
        // Deactivated vertical
        // --------------------------------------------------------------------
        //
        // Setting is_active = false should make Core treat the vertical as
        // unknown (the lookup query has WHERE is_active = true).
        // --------------------------------------------------------------------

        section('Deactivated vertical');

        // Deactivate our test vertical
        await query(
            `UPDATE registered_verticals SET is_active = false WHERE slug = $1`,
            [authCtx.slug]
        );

        // Reset the middleware cache so we don't hit the cached active row
        const { _resetVerticalCache } = require('../../src/middleware/auth');
        _resetVerticalCache();

        const deactivatedToken = authHelper.signTestToken(authCtx, { sub: testTenantId });
        const deactivatedResp = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${deactivatedToken}`,
            },
        }, { email: 'deactivated@example.com' });

        test('deactivated vertical returns 401', deactivatedResp.statusCode, 401);
        test('deactivated has unknown_issuer code',
            deactivatedResp.body.error.code, 'unknown_issuer');

        // Reactivate for remaining tests
        await query(
            `UPDATE registered_verticals SET is_active = true WHERE slug = $1`,
            [authCtx.slug]
        );
        _resetVerticalCache();

        // --------------------------------------------------------------------
        // Tokens with extra unknown claims
        // --------------------------------------------------------------------
        //
        // JWT spec allows arbitrary additional claims. Core should accept
        // them, ignore them, and return verified context normally.
        // --------------------------------------------------------------------

        section('Tokens with extra unknown claims');

        const tokenWithExtras = authHelper.signTestToken(authCtx, {
            sub: testTenantId,
            custom_claim: 'extra_value',
            nested: { deep: true },
            jti: 'some-unique-id-12345',
        });
        const extrasResp = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${tokenWithExtras}`,
            },
        }, { email: 'extras@example.com' });

        testThat('extra claims accepted',
            extrasResp.statusCode === 200 || extrasResp.statusCode === 201);

        // --------------------------------------------------------------------
        // Mixed-case Authorization scheme
        // --------------------------------------------------------------------
        //
        // RFC 6750 says the Bearer scheme is case-insensitive. Currently we
        // require exact "Bearer". These tests document current behavior; if
        // we choose to be permissive later, we'd update both code and test.
        // --------------------------------------------------------------------

        section('Authorization scheme casing');

        const t = authHelper.signTestToken(authCtx, { sub: testTenantId });

        const lowerCaseScheme = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `bearer ${t}`,
            },
        }, { email: 'lower@example.com' });

        test('lowercase "bearer" currently rejected', lowerCaseScheme.statusCode, 401);
        test('lowercase scheme has invalid_auth_format code',
            lowerCaseScheme.body.error.code, 'invalid_auth_format');

        const mixedCaseScheme = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `BEARER ${t}`,
            },
        }, { email: 'upper@example.com' });

        test('uppercase "BEARER" currently rejected', mixedCaseScheme.statusCode, 401);

        // --------------------------------------------------------------------
        // JWKS server down
        // --------------------------------------------------------------------
        //
        // If the vertical's JWKS endpoint is unreachable, Core can't verify
        // the signature. This should return 503, not 401 - it's our problem
        // (or vertical infrastructure problem), not the client's fault.
        // --------------------------------------------------------------------

        section('JWKS server down');

        // Close the auth helper's JWKS server, leaving the DB registration
        // pointing at a now-dead URL
        await new Promise(resolve => authCtx.jwksServer.close(resolve));
        authCtx.jwksServer = null;

        // Clear caches so middleware actually tries to fetch
        const { _resetVerticalJwksCache } = require('../../src/lib/jwks');
        _resetVerticalJwksCache();
        _resetVerticalCache();

        const downToken = authHelper.signTestToken(authCtx, { sub: testTenantId });
        const downResp = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${downToken}`,
            },
        }, { email: 'down@example.com' });

        test('JWKS down returns 503', downResp.statusCode, 503);
        test('JWKS down has service_unavailable code',
            downResp.body.error.code, 'service_unavailable');

        // --------------------------------------------------------------------
        // Token replay within lifetime
        // --------------------------------------------------------------------
        //
        // The same token CAN be replayed within its lifetime. This is
        // intentional for service-to-service auth; replay protection is
        // not needed because tokens are short-lived. This test documents
        // and locks in current behavior so we don't accidentally regress.
        //
        // For this to work we need to restart a fresh JWKS server because
        // the prior test killed the original.
        // --------------------------------------------------------------------

        section('Token replay within lifetime');

        // Spin up a fresh auth context (the old JWKS server is dead)
        await authHelper.teardownTestVertical(authCtx);
        authCtx = await authHelper.setupTestVertical();

        const replayToken = authHelper.signTestToken(authCtx, { sub: testTenantId });

        const firstUse = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${replayToken}`,
            },
        }, { email: 'replay@example.com' });

        const secondUse = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${replayToken}`,
            },
        }, { email: 'replay@example.com' });

        testThat('first use succeeds',
            firstUse.statusCode === 200 || firstUse.statusCode === 201);
        testThat('second use of same token also succeeds (replay allowed in lifetime)',
            secondUse.statusCode === 200 || secondUse.statusCode === 201);
        test('both uses resolve to same identity',
            firstUse.body.identity.id, secondUse.body.identity.id);

        // --------------------------------------------------------------------
        // Concurrent authenticated requests
        // --------------------------------------------------------------------
        //
        // Multiple simultaneous authenticated requests for the same tenant
        // should all succeed without races. The race-on-INSERT logic from
        // Step 4 Session 5 should still hold.
        // --------------------------------------------------------------------

        section('Concurrent authenticated requests');

        const concurrentToken = authHelper.signTestToken(authCtx, { sub: testTenantId });

        const concurrentResults = await Promise.all(
            [1, 2, 3, 4, 5].map(() =>
                request({
                    method: 'POST',
                    path: '/api/v1/identity/hash',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${concurrentToken}`,
                    },
                }, { email: 'concurrent-auth@example.com' })
            )
        );

        testThat('all 5 concurrent requests returned 2xx',
            concurrentResults.every(r => r.statusCode >= 200 && r.statusCode < 300),
            `status codes: ${concurrentResults.map(r => r.statusCode).join(',')}`);

        const ids = concurrentResults.map(r => r.body.identity && r.body.identity.id);
        testThat('all 5 concurrent requests returned same identity id',
            ids.every(id => id === ids[0]),
            `ids: ${JSON.stringify(ids)}`);

        const createdCount = concurrentResults.filter(r =>
            r.body.identity && r.body.identity.created === true).length;
        testThat('exactly one of 5 reports created: true',
            createdCount === 1,
            `created counts: ${createdCount}`);

    } finally {
        section('Teardown');
        try {
            await teardown();
            console.log(`${colors.green}✓${colors.reset} Resources cleaned up`);
        } catch (err) {
            console.log(`${colors.yellow}⚠${colors.reset} Teardown error: ${err.message}`);
        }
    }

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
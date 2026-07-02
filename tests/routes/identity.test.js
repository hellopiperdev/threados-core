// ============================================================================
// ThreadOS Core - Identity Route Tests
// ============================================================================
//
// HTTP integration tests for POST /api/v1/identity/hash. Exercises the full
// stack: signed JWT auth, request validation, identity resolution, response
// shape, error handling.
//
// All requests go through real JWT verification using the test auth helper.
//
// Usage:
//   node tests/routes/identity.test.js
// ============================================================================

require('dotenv').config();

const http = require('http');
const { createServer } = require('../../src/server');
const { query, shutdown } = require('../../src/lib/db');
const authHelper = require('../helpers/auth');

const TEST_PORT = 3001;
const TEST_TENANT_SLUG = '_test_tenant_routes';
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
//
// Builds an HTTP request with optional auth. If `authToken` is provided,
// adds Authorization: Bearer <token>. If `authToken` is null, sends no
// auth (used for testing missing-auth scenarios).
// ----------------------------------------------------------------------------

function request(options, body, authToken) {
    return new Promise((resolve, reject) => {
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers,
        };
        if (authToken !== null && authToken !== undefined) {
            headers['Authorization'] = `Bearer ${authToken}`;
        }

        const req = http.request({
            hostname: 'localhost',
            port: TEST_PORT,
            ...options,
            headers,
        }, (res) => {
            let data = '';
            res.on('data', chunk => { data += chunk; });
            res.on('end', () => {
                let parsedBody = data;
                const contentType = res.headers['content-type'] || '';
                if (contentType.includes('application/json') && data.length > 0) {
                    try {
                        parsedBody = JSON.parse(data);
                    } catch (err) {
                        // leave as string
                    }
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
// Setup and teardown
// ----------------------------------------------------------------------------

async function setup() {
    // Clean any prior test tenant
    await query(`DELETE FROM tenants WHERE slug = $1`, [TEST_TENANT_SLUG]);

    // Create test tenant
    const result = await query(
        `INSERT INTO tenants (slug, display_name, vertical_module)
         VALUES ($1, 'Routes Test Tenant', 'test')
         RETURNING id`,
        [TEST_TENANT_SLUG]
    );
    testTenantId = result.rows[0].id;

    // Set up auth context (test vertical with JWKS server)
    authCtx = await authHelper.setupTestVertical();

    // Start the app server
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
            // audit_log has no FKs (by design) - clean explicitly.
            await query(`DELETE FROM audit_log WHERE tenant_id = $1`, [testTenantId]);
            await query(`DELETE FROM tenants WHERE slug = $1`, [TEST_TENANT_SLUG]);
        } catch (err) {
            console.log(`${colors.yellow}⚠${colors.reset} Cleanup failed: ${err.message}`);
        }
    }
    await shutdown();
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

async function runTests() {
    console.log(`${colors.bold}ThreadOS Core - Identity Route Tests${colors.reset}`);

    try {
        section('Setup');
        await setup();
        console.log(`${colors.green}✓${colors.reset} Test server running on port ${TEST_PORT}`);
        console.log(`${colors.green}✓${colors.reset} Test tenant created: ${testTenantId}`);
        console.log(`${colors.green}✓${colors.reset} Test vertical registered: ${authCtx.slug}`);

        // Pre-build a valid token for happy-path tests
        const validToken = authHelper.signTestToken(authCtx, { sub: testTenantId });

        // --------------------------------------------------------------------
        // Health check (sanity, no auth)
        // --------------------------------------------------------------------

        section('Health check (sanity)');

        const health = await request({
            method: 'GET',
            path: '/api/v1/health',
        }, undefined, null);

        test('health endpoint returns 200', health.statusCode, 200);
        test('health endpoint returns status ok', health.body.status, 'ok');

        // --------------------------------------------------------------------
        // Errors: auth
        // --------------------------------------------------------------------

        section('Errors: auth');

        const noAuth = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
        }, { email: 'test@example.com' }, null);

        test('no Authorization header returns 401', noAuth.statusCode, 401);
        test('missing auth has missing_auth code', noAuth.body.error.code, 'missing_auth');

        const garbageToken = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
        }, { email: 'test@example.com' }, 'not-a-real-jwt');

        test('garbage token returns 401', garbageToken.statusCode, 401);
        test('garbage token has token_malformed code', garbageToken.body.error.code, 'token_malformed');

        const nonexistentTenantToken = authHelper.signTestToken(authCtx, {
            sub: '00000000-0000-0000-0000-000000000000',
        });
        const nonexistentTenantResp = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
        }, { email: 'test@example.com' }, nonexistentTenantToken);

        test('nonexistent tenant returns 404', nonexistentTenantResp.statusCode, 404);
        test('nonexistent tenant has tenant_not_found code',
            nonexistentTenantResp.body.error.code, 'tenant_not_found');

        // --------------------------------------------------------------------
        // Errors: request validation
        // --------------------------------------------------------------------

        section('Errors: request validation');

        const emptyBody = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
        }, {}, validToken);

        test('empty body returns 400', emptyBody.statusCode, 400);
        test('empty body has validation_failed code',
            emptyBody.body.error.code, 'validation_failed');
        testThat('empty body lists missing_identifier',
            emptyBody.body.error.details.some(d => d.code === 'missing_identifier'));

        const malformedEmail = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
        }, { email: 'not-an-email' }, validToken);

        test('malformed email returns 400', malformedEmail.statusCode, 400);
        testThat('malformed email lists email field error',
            malformedEmail.body.error.details.some(d => d.field === 'email'));

        const shortPhone = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
        }, { phone: '12' }, validToken);

        test('short phone returns 400', shortPhone.statusCode, 400);
        testThat('short phone lists phone field error',
            shortPhone.body.error.details.some(d => d.field === 'phone'));

        const nonStringEmail = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
        }, { email: 12345 }, validToken);

        test('non-string email returns 400', nonStringEmail.statusCode, 400);
        testThat('non-string email lists type error',
            nonStringEmail.body.error.details.some(d => d.field === 'email' && d.code === 'invalid_type'));

        // --------------------------------------------------------------------
        // Success: create new identity
        // --------------------------------------------------------------------

        section('Success: create new identity');

        const created = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
        }, {
            email: 'route-test-new@example.com',
            phone: '5551234567',
            name: 'Route Test New',
        }, validToken);

        test('new identity returns 201', created.statusCode, 201);
        testThat('response has identity object', created.body.identity);
        testThat('identity has id', created.body.identity && created.body.identity.id);
        test('created flag is true', created.body.identity.created, true);
        testThat('display_email is sanitized',
            created.body.identity.display_email &&
            created.body.identity.display_email.includes('*'));
        testThat('display_phone is sanitized',
            created.body.identity.display_phone &&
            created.body.identity.display_phone.includes('*'));
        test('display_name is preserved', created.body.identity.display_name, 'Route Test New');

        // Privacy guarantees: raw PII and hashes must not appear
        const responseString = JSON.stringify(created.body);
        testThat('response does NOT contain raw email',
            !responseString.includes('route-test-new@example.com'));
        testThat('response does NOT contain email_hash field',
            !responseString.includes('email_hash'));
        testThat('response does NOT contain phone_hash field',
            !responseString.includes('phone_hash'));

        // --------------------------------------------------------------------
        // Success: find existing identity
        // --------------------------------------------------------------------

        section('Success: find existing identity');

        const findAgain = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
        }, {
            email: 'route-test-new@example.com',
            phone: '5551234567',
        }, validToken);

        test('existing identity returns 200', findAgain.statusCode, 200);
        test('same identity id',
            findAgain.body.identity.id, created.body.identity.id);
        test('created flag is false', findAgain.body.identity.created, false);

        const caseInsensitive = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
        }, {
            email: 'ROUTE-TEST-NEW@EXAMPLE.COM',
        }, validToken);

        test('case-insensitive match',
            caseInsensitive.body.identity.id, created.body.identity.id);
        test('case-insensitive not created', caseInsensitive.body.identity.created, false);

        // --------------------------------------------------------------------
        // Response headers
        // --------------------------------------------------------------------

        section('Response headers');

        testThat('response includes X-Service header',
            created.headers['x-service'] === 'threados-core');
        testThat('response uses JSON content type',
            (created.headers['content-type'] || '').includes('application/json'));

    } finally {
        section('Teardown');
        try {
            await teardown();
            console.log(`${colors.green}✓${colors.reset} Server stopped and tenant cleaned up`);
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
// ============================================================================
// ThreadOS Core - Robustness Tests
// ============================================================================
//
// Tests edge cases for the /api/v1/identity/hash endpoint. All requests use
// real JWT auth via the test helper. Covers behaviors the basic route tests
// don't: malformed JSON, oversized payloads, wrong Content-Type, control
// characters in input, SQL injection attempts, and information disclosure.
//
// Usage:
//   node tests/routes/robustness.test.js
// ============================================================================

require('dotenv').config();

const http = require('http');
const { createServer } = require('../../src/server');
const { query, shutdown } = require('../../src/lib/db');
const authHelper = require('../helpers/auth');

const TEST_PORT = 3002;
const TEST_TENANT_SLUG = '_test_tenant_robustness';
let testTenantId = null;
let authCtx = null;
let server = null;
let validToken = null;

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
// HTTP helper that accepts raw bodies and custom headers
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
                    try {
                        parsedBody = JSON.parse(data);
                    } catch (err) {
                        // leave as string if not parseable
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
// Setup / teardown
// ----------------------------------------------------------------------------

async function setup() {
    await query(`DELETE FROM tenants WHERE slug = $1`, [TEST_TENANT_SLUG]);

    const result = await query(
        `INSERT INTO tenants (slug, display_name, vertical_module)
         VALUES ($1, 'Robustness Test Tenant', 'test')
         RETURNING id`,
        [TEST_TENANT_SLUG]
    );
    testTenantId = result.rows[0].id;

    authCtx = await authHelper.setupTestVertical();
    validToken = authHelper.signTestToken(authCtx, { sub: testTenantId });

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
    console.log(`${colors.bold}ThreadOS Core - Robustness Tests${colors.reset}`);

    try {
        section('Setup');
        await setup();
        console.log(`${colors.green}✓${colors.reset} Test server running on port ${TEST_PORT}`);
        console.log(`${colors.green}✓${colors.reset} Test tenant: ${testTenantId}`);
        console.log(`${colors.green}✓${colors.reset} Test vertical: ${authCtx.slug}`);

        // Pre-build authed headers for tests that need a normal request
        const authedHeaders = {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${validToken}`,
        };

        // --------------------------------------------------------------------
        // Header hardening
        // --------------------------------------------------------------------

        section('Headers: information disclosure');

        const normalResponse = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
            headers: authedHeaders,
        }, { email: 'header-test@example.com' });

        testThat('X-Powered-By header is NOT exposed',
            !normalResponse.headers['x-powered-by'],
            'should not reveal Express framework');

        // --------------------------------------------------------------------
        // Malformed JSON
        // --------------------------------------------------------------------

        section('Malformed JSON');

        const badJson = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
            headers: authedHeaders,
        }, '{not valid json');

        test('malformed JSON returns 400 (not 500)', badJson.statusCode, 400);
        test('malformed JSON has invalid_json code',
            badJson.body.error.code, 'invalid_json');

        const truncatedJson = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
            headers: authedHeaders,
        }, '{"email":"test@example.com"');

        test('truncated JSON returns 400', truncatedJson.statusCode, 400);
        test('truncated JSON has invalid_json code',
            truncatedJson.body.error.code, 'invalid_json');

        // --------------------------------------------------------------------
        // Oversized payload
        // --------------------------------------------------------------------

        section('Oversized payload');

        const hugeName = 'A'.repeat(200000);
        const hugePayload = JSON.stringify({ email: 'big@example.com', name: hugeName });

        const oversized = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
            headers: authedHeaders,
        }, hugePayload);

        test('oversized payload returns 413', oversized.statusCode, 413);
        test('oversized payload has payload_too_large code',
            oversized.body.error.code, 'payload_too_large');

        // --------------------------------------------------------------------
        // Wrong Content-Type
        // --------------------------------------------------------------------

        section('Wrong Content-Type');

        const noContentType = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
            headers: { 'Authorization': `Bearer ${validToken}` },
        }, { email: 'test@example.com' });

        test('missing Content-Type returns 415', noContentType.statusCode, 415);
        test('missing Content-Type has unsupported_media_type code',
            noContentType.body.error.code, 'unsupported_media_type');

        const wrongContentType = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
            headers: {
                'Content-Type': 'text/plain',
                'Authorization': `Bearer ${validToken}`,
            },
        }, 'not json');

        test('non-JSON Content-Type returns 415', wrongContentType.statusCode, 415);

        // --------------------------------------------------------------------
        // Control characters in input
        // --------------------------------------------------------------------

        section('Control characters in input');

        const nullByte = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
            headers: authedHeaders,
        }, { email: 'nullbyte@example.com', name: 'Alice\u0000Hidden' });

        test('null byte in name returns 400', nullByte.statusCode, 400);
        test('null byte returns validation_failed',
            nullByte.body.error.code, 'validation_failed');
        testThat('null byte error mentions invalid characters',
            nullByte.body.error.details.some(d =>
                d.field === 'name' && d.code === 'invalid_characters'));

        const verticalTab = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
            headers: authedHeaders,
        }, { email: 'vtab@example.com', name: 'Alice\u000BHidden' });

        test('vertical tab in name returns 400', verticalTab.statusCode, 400);

        const unicode = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
            headers: authedHeaders,
        }, { email: 'unicode-robust@example.com', name: 'María José 🌟 李明' });

        test('valid unicode in name returns 201', unicode.statusCode, 201);
        test('unicode preserved in display_name',
            unicode.body.identity.display_name, 'María José 🌟 李明');

        // --------------------------------------------------------------------
        // SQL injection attempts
        // --------------------------------------------------------------------

        section('SQL injection attempts');

        const injectionInName = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
            headers: authedHeaders,
        }, {
            email: 'sqli-test@example.com',
            name: "Robert'); DROP TABLE identities; --",
        });

        test('SQL injection in name is treated as data',
            injectionInName.statusCode, 201);
        test('injection string stored verbatim',
            injectionInName.body.identity.display_name,
            "Robert'); DROP TABLE identities; --");

        const tableCheck = await query(
            `SELECT count(*) AS count FROM identities WHERE tenant_id = $1`,
            [testTenantId]
        );
        testThat('identities table still intact after injection attempt',
            parseInt(tableCheck.rows[0].count, 10) > 0);

        const injectionInEmail = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
            headers: authedHeaders,
        }, { email: "alice@example.com'; DROP TABLE identities; --" });

        test('SQL injection in email is rejected by validation',
            injectionInEmail.statusCode, 400);
        testThat('email injection rejected for invalid format',
            injectionInEmail.body.error.details.some(d =>
                d.field === 'email' && d.code === 'invalid_format'));

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
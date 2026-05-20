// ============================================================================
// ThreadOS Core - Identity Route Tests (HTTP Integration)
// ============================================================================
//
// Exercises the /api/v1/identity/hash endpoint via real HTTP requests.
// This is the highest-level test in our suite - it verifies that the entire
// stack works together: Express routing, validation, business logic, database
// access, and response shaping.
//
// The test script starts its own Express server on port 3001, runs tests,
// and shuts down cleanly.
//
// Usage:
//   node tests/routes/identity.test.js
// ============================================================================

require('dotenv').config();

const http = require('http');
const { createServer } = require('../../src/server');
const { query, shutdown } = require('../../src/lib/db');

const TEST_PORT = 3001;
const TEST_TENANT_SLUG = '_test_tenant_route_session_4';
let testTenantId = null;
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
// Makes an HTTP request and returns { statusCode, headers, body }.
// Body is parsed as JSON if Content-Type is application/json.
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
// Setup and teardown
// ----------------------------------------------------------------------------

async function setup() {
    // Clean up any leftover from previous failed runs
    await query(`DELETE FROM tenants WHERE slug = $1`, [TEST_TENANT_SLUG]);

    // Create a test tenant
    const result = await query(
        `INSERT INTO tenants (slug, display_name, vertical_module)
         VALUES ($1, 'Route Test Tenant', 'test')
         RETURNING id`,
        [TEST_TENANT_SLUG]
    );
    testTenantId = result.rows[0].id;

    // Start the server
    const app = createServer();
    server = app.listen(TEST_PORT);

    // Wait for server to be ready
    await new Promise((resolve) => {
        server.on('listening', resolve);
        if (server.listening) resolve();
    });
}

async function teardown() {
    if (server) {
        await new Promise(resolve => server.close(resolve));
    }
    if (testTenantId) {
        try {
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

        // --------------------------------------------------------------------
        // Health check (sanity)
        // --------------------------------------------------------------------

        section('Health check (sanity)');

        const health = await request({
            method: 'GET',
            path: '/api/v1/health',
        });
        test('health endpoint returns 200', health.statusCode, 200);
        test('health endpoint returns status ok', health.body.status, 'ok');

        // --------------------------------------------------------------------
        // Error: missing tenant header
        // --------------------------------------------------------------------

        section('Errors: tenant context');

        const noTenant = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
            headers: { 'Content-Type': 'application/json' },
        }, { email: 'a@b.com' });

        test('no tenant header returns 400', noTenant.statusCode, 400);
        test('no tenant header has invalid_tenant code',
            noTenant.body.error.code, 'invalid_tenant');

        const invalidTenant = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
            headers: {
                'Content-Type': 'application/json',
                'X-Tenant-Id': 'not-a-uuid',
            },
        }, { email: 'a@b.com' });

        test('invalid tenant UUID returns 400', invalidTenant.statusCode, 400);
        test('invalid tenant UUID has invalid_tenant code',
            invalidTenant.body.error.code, 'invalid_tenant');

        const nonexistentTenant = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
            headers: {
                'Content-Type': 'application/json',
                'X-Tenant-Id': '00000000-0000-0000-0000-000000000000',
            },
        }, { email: 'a@b.com' });

        test('nonexistent tenant returns 404', nonexistentTenant.statusCode, 404);
        test('nonexistent tenant has tenant_not_found code',
            nonexistentTenant.body.error.code, 'tenant_not_found');

        // --------------------------------------------------------------------
        // Error: invalid request body
        // --------------------------------------------------------------------

        section('Errors: request validation');

        const emptyBody = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
            headers: {
                'Content-Type': 'application/json',
                'X-Tenant-Id': testTenantId,
            },
        }, {});

        test('empty body returns 400', emptyBody.statusCode, 400);
        test('empty body has validation_failed code',
            emptyBody.body.error.code, 'validation_failed');
        testThat('empty body lists missing_identifier',
            emptyBody.body.error.details.some(d => d.code === 'missing_identifier'));

        const badEmail = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
            headers: {
                'Content-Type': 'application/json',
                'X-Tenant-Id': testTenantId,
            },
        }, { email: 'not-an-email' });

        test('malformed email returns 400', badEmail.statusCode, 400);
        testThat('malformed email lists email field error',
            badEmail.body.error.details.some(d => d.field === 'email' && d.code === 'invalid_format'));

        const badPhone = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
            headers: {
                'Content-Type': 'application/json',
                'X-Tenant-Id': testTenantId,
            },
        }, { phone: '123' });

        test('short phone returns 400', badPhone.statusCode, 400);
        testThat('short phone lists phone field error',
            badPhone.body.error.details.some(d => d.field === 'phone' && d.code === 'invalid_format'));

        const wrongType = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
            headers: {
                'Content-Type': 'application/json',
                'X-Tenant-Id': testTenantId,
            },
        }, { email: 12345 });

        test('non-string email returns 400', wrongType.statusCode, 400);
        testThat('non-string email lists type error',
            wrongType.body.error.details.some(d => d.code === 'invalid_type'));

        // --------------------------------------------------------------------
        // Success: create new identity
        // --------------------------------------------------------------------

        section('Success: create new identity');

        const created = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
            headers: {
                'Content-Type': 'application/json',
                'X-Tenant-Id': testTenantId,
            },
        }, {
            email: 'newuser@example.com',
            phone: '555-444-1234',
            name: 'New User',
        });

        test('new identity returns 201', created.statusCode, 201);
        testThat('response has identity object',
            created.body.identity && typeof created.body.identity === 'object');
        testThat('identity has id', created.body.identity.id);
        test('created flag is true', created.body.identity.created, true);
        test('display_email is sanitized',
            created.body.identity.display_email, 'n*****@example.com');
        test('display_phone is sanitized',
            created.body.identity.display_phone, '***-***-1234');
        test('display_name is preserved', created.body.identity.display_name, 'New User');

        // Verify we never expose raw PII or hashes in the response
        const responseJson = JSON.stringify(created.body);
        testThat('response does NOT contain raw email',
            !responseJson.includes('newuser@example.com'),
            'raw email leaked in response!');
        testThat('response does NOT contain email_hash field',
            !responseJson.includes('email_hash'));
        testThat('response does NOT contain phone_hash field',
            !responseJson.includes('phone_hash'));

        // --------------------------------------------------------------------
        // Success: find existing identity (idempotent)
        // --------------------------------------------------------------------

        section('Success: find existing identity');

        const found = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
            headers: {
                'Content-Type': 'application/json',
                'X-Tenant-Id': testTenantId,
            },
        }, {
            email: 'newuser@example.com',
        });

        test('existing identity returns 200', found.statusCode, 200);
        test('same identity id', found.body.identity.id, created.body.identity.id);
        test('created flag is false', found.body.identity.created, false);

        // Case-insensitive match should still find the same identity
        const caseFound = await request({
            method: 'POST',
            path: '/api/v1/identity/hash',
            headers: {
                'Content-Type': 'application/json',
                'X-Tenant-Id': testTenantId,
            },
        }, {
            email: 'NEWUSER@EXAMPLE.COM',
        });

        test('case-insensitive match', caseFound.body.identity.id, created.body.identity.id);
        test('case-insensitive not created', caseFound.body.identity.created, false);

        // --------------------------------------------------------------------
        // Response headers
        // --------------------------------------------------------------------

        section('Response headers');

        test('response includes X-Service header',
            created.headers['x-service'], 'threados-core');
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
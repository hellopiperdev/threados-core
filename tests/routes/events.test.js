// ============================================================================
// ThreadOS Core - Event Route Tests
// ============================================================================
//
// HTTP integration tests for POST /api/v1/events. Exercises the full stack:
// signed JWT auth, single + batch capture, validation, PII rejection, registry
// enforcement, idempotency, and error shaping.
//
// All requests go through real JWT verification using the test auth helper.
//
// Usage:
//   node tests/routes/events.test.js
// ============================================================================

require('dotenv').config();

const crypto = require('crypto');
const http = require('http');
const { createServer } = require('../../src/server');
const { query, shutdown } = require('../../src/lib/db');
const authHelper = require('../helpers/auth');

const TEST_PORT = 3002;
const TEST_TENANT_SLUG = '_test_tenant_events_routes';
let testTenantId = null;
let testIdentityId = null;
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
// HTTP request helper (mirrors tests/routes/identity.test.js)
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
                    try { parsedBody = JSON.parse(data); } catch (err) { /* leave as string */ }
                }
                resolve({ statusCode: res.statusCode, headers: res.headers, body: parsedBody });
            });
        });

        req.on('error', reject);
        if (body !== undefined) {
            req.write(typeof body === 'string' ? body : JSON.stringify(body));
        }
        req.end();
    });
}

function makeEvent(overrides = {}) {
    return {
        event_id: crypto.randomUUID(),
        event_name: 'page_viewed',
        event_category: 'engagement',
        source_type: 'web',
        event_timestamp: '2026-06-26T12:00:00.000Z',
        session_id: crypto.randomUUID(),
        properties: { path: '/home' },
        ...overrides,
    };
}

const SEED_EVENT_TYPES = [
    { event_name: 'page_viewed', event_category: 'engagement' },
    { event_name: 'purchase_completed', event_category: 'commerce' },
];

// ----------------------------------------------------------------------------
// Setup and teardown
// ----------------------------------------------------------------------------

async function setup() {
    await query(`DELETE FROM tenants WHERE slug = $1`, [TEST_TENANT_SLUG]);

    const result = await query(
        `INSERT INTO tenants (slug, display_name, vertical_module)
         VALUES ($1, 'Events Routes Test Tenant', 'test') RETURNING id`,
        [TEST_TENANT_SLUG]
    );
    testTenantId = result.rows[0].id;

    for (const et of SEED_EVENT_TYPES) {
        await query(
            `INSERT INTO event_type_registry (tenant_id, event_name, event_category)
             VALUES ($1, $2, $3) ON CONFLICT (tenant_id, event_name) DO NOTHING`,
            [testTenantId, et.event_name, et.event_category]
        );
    }

    const idn = await query(
        `INSERT INTO identities (tenant_id, email_hash, resolution_key, match_source)
         VALUES ($1, $2, $3, 'deterministic') RETURNING id`,
        [testTenantId, 'c'.repeat(64), 'd'.repeat(64)]
    );
    testIdentityId = idn.rows[0].id;

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
    console.log(`${colors.bold}ThreadOS Core - Event Route Tests${colors.reset}`);

    try {
        section('Setup');
        await setup();
        console.log(`${colors.green}✓${colors.reset} Test server on port ${TEST_PORT}`);
        console.log(`${colors.green}✓${colors.reset} Test tenant: ${testTenantId}`);
        console.log(`${colors.green}✓${colors.reset} Test vertical: ${authCtx.slug}`);

        const validToken = authHelper.signTestToken(authCtx, { sub: testTenantId });
        const PATH = '/api/v1/events';

        // --------------------------------------------------------------------
        section('Errors: auth');
        // --------------------------------------------------------------------

        const noAuth = await request({ method: 'POST', path: PATH }, makeEvent(), null);
        test('no auth returns 401', noAuth.statusCode, 401);
        test('no auth has missing_auth code', noAuth.body.error.code, 'missing_auth');

        const garbage = await request({ method: 'POST', path: PATH }, makeEvent(), 'not-a-jwt');
        test('garbage token returns 401', garbage.statusCode, 401);

        // An expired token must be rejected by the same middleware the identity
        // route uses. The middleware has unit coverage for this; this is the
        // events-route integration proof. (Pattern mirrors tests/middleware/auth.)
        const nowSec = Math.floor(Date.now() / 1000);
        const expiredToken = authHelper.signTestToken(authCtx, {
            sub: testTenantId,
            iat: nowSec - 7200,
            exp: nowSec - 3600,
        });
        const expired = await request({ method: 'POST', path: PATH }, makeEvent(), expiredToken);
        test('expired token returns 401', expired.statusCode, 401);
        test('expired token has token_expired code', expired.body.error.code, 'token_expired');

        // --------------------------------------------------------------------
        section('Errors: content type');
        // --------------------------------------------------------------------

        const wrongType = await request(
            { method: 'POST', path: PATH, headers: { 'Content-Type': 'text/plain' } },
            'plain text', validToken
        );
        test('non-JSON content type returns 415', wrongType.statusCode, 415);

        // --------------------------------------------------------------------
        section('Errors: validation');
        // --------------------------------------------------------------------

        const missingId = await request({ method: 'POST', path: PATH },
            makeEvent({ event_id: undefined }), validToken);
        test('missing event_id returns 400', missingId.statusCode, 400);
        test('missing event_id has validation_failed code',
            missingId.body.error.code, 'validation_failed');
        testThat('missing event_id lists event_id detail',
            missingId.body.error.details.some(d => d.field === 'event_id'));

        const noIdentifier = await request({ method: 'POST', path: PATH },
            makeEvent({ session_id: undefined }), validToken);
        test('no identifier returns 400', noIdentifier.statusCode, 400);
        testThat('no identifier lists missing_identifier',
            noIdentifier.body.error.details.some(d => d.code === 'missing_identifier'));

        const badTimestamp = await request({ method: 'POST', path: PATH },
            makeEvent({ event_timestamp: 'yesterday' }), validToken);
        test('bad timestamp returns 400', badTimestamp.statusCode, 400);

        // session_id is opaque (Core does not own its format): a non-UUID
        // session ID, as produced by Express/Rails/SDK session stores, is
        // accepted end-to-end. The example below is a URL-encoded, signed
        // Express session cookie value - exactly the kind of opaque string that
        // would have 500'd against the old UUID column (migration 004).
        const opaqueSessionId = 's%3AABC123.sig';
        const opaqueEvt = makeEvent({ session_id: opaqueSessionId });
        const opaqueSession = await request({ method: 'POST', path: PATH },
            opaqueEvt, validToken);
        test('opaque (non-UUID) session_id returns 201', opaqueSession.statusCode, 201);
        test('opaque session_id created count 1', opaqueSession.body.created, 1);

        // Round-trip: the value must persist intact, neither rejected nor
        // mangled (no lowercasing, no reformatting).
        const opaquePersisted = await query(
            `SELECT session_id FROM events WHERE tenant_id = $1 AND event_id = $2`,
            [testTenantId, opaqueEvt.event_id]
        );
        test('opaque session_id persisted intact',
            opaquePersisted.rows[0].session_id, opaqueSessionId);

        // Control characters in an opaque identifier are rejected - that's a
        // shape Core does legitimately own.
        const ctrlSession = await request({ method: 'POST', path: PATH },
            makeEvent({ session_id: 'sess\x00bad' }), validToken);
        test('control-character session_id returns 400', ctrlSession.statusCode, 400);
        testThat('control-character session_id lists invalid_characters',
            ctrlSession.body.error.details.some(
                d => d.field === 'session_id' && d.code === 'invalid_characters'));

        const ctrlFingerprint = await request({ method: 'POST', path: PATH },
            makeEvent({ session_id: undefined, device_fingerprint: 'fp\x07bad' }), validToken);
        test('control-character device_fingerprint returns 400', ctrlFingerprint.statusCode, 400);
        testThat('control-character device_fingerprint lists invalid_characters',
            ctrlFingerprint.body.error.details.some(
                d => d.field === 'device_fingerprint' && d.code === 'invalid_characters'));

        // --------------------------------------------------------------------
        section('Errors: PII in properties (Decision 10)');
        // --------------------------------------------------------------------

        const piiEmail = await request({ method: 'POST', path: PATH },
            makeEvent({ properties: { email: 'jane@example.com' } }), validToken);
        test('PII email returns 400', piiEmail.statusCode, 400);
        testThat('PII email flagged as pii_detected',
            piiEmail.body.error.details.some(d => d.code === 'pii_detected'));
        testThat('PII value is NOT echoed back in the error',
            !JSON.stringify(piiEmail.body).includes('jane@example.com'),
            'error response must not leak the raw PII it rejected');

        // PII smuggled into a property KEY must be rejected too (Gap 1). A bare
        // {"jane@example.com": "clicked"} previously passed and persisted the email.
        const piiKey = await request({ method: 'POST', path: PATH },
            makeEvent({ properties: { 'jane@example.com': 'clicked' } }), validToken);
        test('PII in a property key returns 400', piiKey.statusCode, 400);
        testThat('PII key flagged as pii_detected',
            piiKey.body.error.details.some(d => d.code === 'pii_detected'));
        testThat('PII key text is NOT echoed back in the error',
            !JSON.stringify(piiKey.body).includes('jane@example.com'),
            'error response must not leak the raw PII key it rejected');

        // International phone numbers must be caught, not just US formats (Gap 2).
        const piiIntlPhone = await request({ method: 'POST', path: PATH },
            makeEvent({ properties: { note: '+44 20 7946 0958' } }), validToken);
        test('international phone in properties returns 400', piiIntlPhone.statusCode, 400);
        testThat('international phone flagged as pii_detected',
            piiIntlPhone.body.error.details.some(d => d.code === 'pii_detected'));

        // --------------------------------------------------------------------
        section('Errors: unregistered event (Decision 8)');
        // --------------------------------------------------------------------

        const unregistered = await request({ method: 'POST', path: PATH },
            makeEvent({ event_name: 'definitely_not_registered' }), validToken);
        test('unregistered event returns 422', unregistered.statusCode, 422);
        test('unregistered event has unregistered_event code',
            unregistered.body.error.code, 'unregistered_event');

        const mismatch = await request({ method: 'POST', path: PATH },
            makeEvent({ event_name: 'page_viewed', event_category: 'wrong' }), validToken);
        test('category mismatch returns 422', mismatch.statusCode, 422);

        // --------------------------------------------------------------------
        section('Errors: identity / tenant not found');
        // --------------------------------------------------------------------

        const badIdentity = await request({ method: 'POST', path: PATH },
            makeEvent({ identity_id: crypto.randomUUID() }), validToken);
        test('nonexistent identity returns 422', badIdentity.statusCode, 422);
        test('nonexistent identity has identity_not_found code',
            badIdentity.body.error.code, 'identity_not_found');

        const noTenantToken = authHelper.signTestToken(authCtx, {
            sub: '00000000-0000-0000-0000-000000000000',
        });
        const noTenant = await request({ method: 'POST', path: PATH }, makeEvent(), noTenantToken);
        test('nonexistent tenant returns 404', noTenant.statusCode, 404);
        test('nonexistent tenant has tenant_not_found code',
            noTenant.body.error.code, 'tenant_not_found');
        // 404 is produced deep in captureEvents, well past the body parser, so it
        // should carry X-Service like every other Core response.
        testThat('tenant_not_found response carries X-Service header',
            noTenant.headers['x-service'] === 'threados-core');

        // --------------------------------------------------------------------
        section('Success: single event');
        // --------------------------------------------------------------------

        const evt = makeEvent({ identity_id: testIdentityId });
        const created = await request({ method: 'POST', path: PATH }, evt, validToken);
        test('single event returns 201', created.statusCode, 201);
        test('single event created count 1', created.body.created, 1);
        test('single event duplicates count 0', created.body.duplicates, 0);
        test('result status is created', created.body.results[0].status, 'created');
        test('result echoes event_id', created.body.results[0].event_id, evt.event_id);
        testThat('result includes Core id', !!created.body.results[0].id);

        // --------------------------------------------------------------------
        section('Idempotency: replay is a no-op success');
        // --------------------------------------------------------------------

        const replay = await request({ method: 'POST', path: PATH }, evt, validToken);
        test('replay returns 200 (all duplicates)', replay.statusCode, 200);
        test('replay created count 0', replay.body.created, 0);
        test('replay duplicates count 1', replay.body.duplicates, 1);
        test('replay status is duplicate', replay.body.results[0].status, 'duplicate');

        const persistCount = await query(
            `SELECT count(*)::int AS n FROM events WHERE tenant_id = $1 AND event_id = $2`,
            [testTenantId, evt.event_id]
        );
        test('replay did not duplicate the row', persistCount.rows[0].n, 1);

        // --------------------------------------------------------------------
        section('Success: batch');
        // --------------------------------------------------------------------

        const a = makeEvent();
        const b = makeEvent({ event_name: 'purchase_completed', event_category: 'commerce' });
        const batch = await request({ method: 'POST', path: PATH }, [a, b], validToken);
        test('batch returns 201', batch.statusCode, 201);
        test('batch created count 2', batch.body.created, 2);
        test('batch returns two results', batch.body.results.length, 2);

        // --------------------------------------------------------------------
        section('Reject-all: one bad event sinks the batch (Decision 7)');
        // --------------------------------------------------------------------

        const good = makeEvent();
        const rejectAll = await request({ method: 'POST', path: PATH },
            [good, makeEvent({ event_name: 'definitely_not_registered' })], validToken);
        test('batch with one unregistered event returns 422', rejectAll.statusCode, 422);
        testThat('rejection detail carries the offending index',
            rejectAll.body.error.details.some(d => d.index === 1));

        const goodPersisted = await query(
            `SELECT count(*)::int AS n FROM events WHERE tenant_id = $1 AND event_id = $2`,
            [testTenantId, good.event_id]
        );
        test('reject-all persisted nothing from the batch', goodPersisted.rows[0].n, 0);

        // --------------------------------------------------------------------
        section('Errors: malformed JSON and wrong body type');
        // --------------------------------------------------------------------

        // Finding #3: body-parser rejections must carry X-Service. A genuine
        // syntax error is still invalid_json (Finding #4 must not lose this case).
        const badJson = await request({ method: 'POST', path: PATH }, '{not valid', validToken);
        test('malformed JSON returns 400', badJson.statusCode, 400);
        test('malformed JSON has invalid_json code', badJson.body.error.code, 'invalid_json');
        testThat('invalid_json response carries X-Service header (Finding #3)',
            badJson.headers['x-service'] === 'threados-core');

        // Same generality check on a different body-parser rejection: an oversized
        // body fails inside express.json, before any route middleware runs.
        const oversized = await request({ method: 'POST', path: PATH },
            makeEvent({ properties: { blob: 'x'.repeat(150000) } }), validToken);
        test('oversized body returns 413', oversized.statusCode, 413);
        test('oversized body has payload_too_large code',
            oversized.body.error.code, 'payload_too_large');
        testThat('payload_too_large response carries X-Service header (Finding #3)',
            oversized.headers['x-service'] === 'threados-core');

        // Finding #4: valid JSON whose top-level type is not an object/array is
        // NOT invalid_json - it parses fine, the shape is just wrong. Each must
        // come back as invalid_body_type, not invalid_json.
        const stringBody = await request({ method: 'POST', path: PATH }, '"a string"', validToken);
        test('string body returns 400', stringBody.statusCode, 400);
        test('string body has invalid_body_type code',
            stringBody.body.error.code, 'invalid_body_type');

        const numberBody = await request({ method: 'POST', path: PATH }, 42, validToken);
        test('number body returns 400', numberBody.statusCode, 400);
        test('number body has invalid_body_type code',
            numberBody.body.error.code, 'invalid_body_type');

        const nullBody = await request({ method: 'POST', path: PATH }, null, validToken);
        test('null body returns 400', nullBody.statusCode, 400);
        test('null body has invalid_body_type code',
            nullBody.body.error.code, 'invalid_body_type');

        const boolBody = await request({ method: 'POST', path: PATH }, true, validToken);
        test('boolean body returns 400', boolBody.statusCode, 400);
        test('boolean body has invalid_body_type code',
            boolBody.body.error.code, 'invalid_body_type');

        // --------------------------------------------------------------------
        section('Response headers');
        // --------------------------------------------------------------------

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

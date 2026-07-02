// ============================================================================
// ThreadOS Core - Consent Route Tests
// ============================================================================
//
// HTTP integration tests for POST /api/v1/consent. Exercises the full stack:
// signed JWT auth, single + batch recording, validation, PII rejection,
// tenant scoping, projection correctness, and error shaping.
//
// All requests go through real JWT verification using the test auth helper.
//
// Usage:
//   node tests/routes/consent.test.js
// ============================================================================

require('dotenv').config();

const crypto = require('crypto');
const http = require('http');
const { createServer } = require('../../src/server');
const { query, shutdown } = require('../../src/lib/db');
const authHelper = require('../helpers/auth');

const TEST_PORT = 3006;
const TEST_TENANT_SLUG = '_test_tenant_consent_routes';
let testTenantId = null;
let otherTenantId = null;
let testIdentityId = null;
let otherTenantIdentityId = null;
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
// HTTP request helper (mirrors tests/routes/events.test.js)
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

function daysAgo(n) {
    return new Date(Date.now() - n * 24 * 60 * 60 * 1000).toISOString();
}
function daysFromNow(n) {
    return new Date(Date.now() + n * 24 * 60 * 60 * 1000).toISOString();
}

function makeRecord(overrides = {}) {
    return {
        identity_id: testIdentityId,
        purpose: 'marketing',
        vendor: 'acme_dms',
        channel: 'email',
        data_category: 'behavioral',
        jurisdiction: 'US',
        state: 'granted',
        consent_basis: 'active_consent',
        captured_via: 'web_form',
        capture_context: 'Preference center save from account settings page',
        reason: 'Customer opted in via preference center',
        effective_from: daysAgo(10),
        effective_until: null,
        ...overrides,
    };
}

// ----------------------------------------------------------------------------
// Setup and teardown
// ----------------------------------------------------------------------------

async function setup() {
    await query(`DELETE FROM tenants WHERE slug IN ($1, $2)`,
        [TEST_TENANT_SLUG, TEST_TENANT_SLUG + '_other']);

    const result = await query(
        `INSERT INTO tenants (slug, display_name, vertical_module)
         VALUES ($1, 'Consent Routes Test Tenant', 'test') RETURNING id`,
        [TEST_TENANT_SLUG]
    );
    testTenantId = result.rows[0].id;

    const other = await query(
        `INSERT INTO tenants (slug, display_name, vertical_module)
         VALUES ($1, 'Consent Routes Other Tenant', 'test') RETURNING id`,
        [TEST_TENANT_SLUG + '_other']
    );
    otherTenantId = other.rows[0].id;

    const idn = await query(
        `INSERT INTO identities (tenant_id, email_hash, resolution_key, match_source)
         VALUES ($1, $2, $3, 'deterministic') RETURNING id`,
        [testTenantId, '3'.repeat(64), '4'.repeat(64)]
    );
    testIdentityId = idn.rows[0].id;

    const otherIdn = await query(
        `INSERT INTO identities (tenant_id, email_hash, resolution_key, match_source)
         VALUES ($1, $2, $3, 'deterministic') RETURNING id`,
        [otherTenantId, '3'.repeat(64), '4'.repeat(64)]
    );
    otherTenantIdentityId = otherIdn.rows[0].id;

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
    try {
        // audit_log has no FKs (by design) - clean test audit rows explicitly.
        await query(`DELETE FROM audit_log WHERE tenant_id = ANY($1)`,
            [[testTenantId, otherTenantId].filter(Boolean)]);
        await query(`DELETE FROM tenants WHERE slug IN ($1, $2)`,
            [TEST_TENANT_SLUG, TEST_TENANT_SLUG + '_other']);
    } catch (err) {
        console.log(`${colors.yellow}⚠${colors.reset} Cleanup failed: ${err.message}`);
    }
    await shutdown();
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

async function runTests() {
    console.log(`${colors.bold}ThreadOS Core - Consent Route Tests${colors.reset}`);

    try {
        section('Setup');
        await setup();
        console.log(`${colors.green}✓${colors.reset} Test server on port ${TEST_PORT}`);
        console.log(`${colors.green}✓${colors.reset} Test tenant: ${testTenantId}`);
        console.log(`${colors.green}✓${colors.reset} Test vertical: ${authCtx.slug}`);

        const validToken = authHelper.signTestToken(authCtx, { sub: testTenantId });
        const PATH = '/api/v1/consent';

        // --------------------------------------------------------------------
        section('Errors: auth');
        // --------------------------------------------------------------------

        const noAuth = await request({ method: 'POST', path: PATH }, makeRecord(), null);
        test('no auth returns 401', noAuth.statusCode, 401);
        test('no auth has missing_auth code', noAuth.body.error.code, 'missing_auth');

        const garbage = await request({ method: 'POST', path: PATH }, makeRecord(), 'not-a-jwt');
        test('garbage token returns 401', garbage.statusCode, 401);

        const nowSec = Math.floor(Date.now() / 1000);
        const expiredToken = authHelper.signTestToken(authCtx, {
            sub: testTenantId,
            iat: nowSec - 7200,
            exp: nowSec - 3600,
        });
        const expired = await request({ method: 'POST', path: PATH }, makeRecord(), expiredToken);
        test('expired token returns 401', expired.statusCode, 401);
        test('expired token has token_expired code', expired.body.error.code, 'token_expired');

        // --------------------------------------------------------------------
        section('Errors: content type and body shape');
        // --------------------------------------------------------------------

        const wrongType = await request(
            { method: 'POST', path: PATH, headers: { 'Content-Type': 'text/plain' } },
            'plain text', validToken
        );
        test('non-JSON content type returns 415', wrongType.statusCode, 415);

        const badJson = await request({ method: 'POST', path: PATH }, '{not json', validToken);
        test('malformed JSON returns 400', badJson.statusCode, 400);
        test('malformed JSON has invalid_json code', badJson.body.error.code, 'invalid_json');

        const bareString = await request({ method: 'POST', path: PATH }, '"granted"', validToken);
        test('bare JSON string returns 400', bareString.statusCode, 400);
        test('bare JSON string has invalid_body_type code',
            bareString.body.error.code, 'invalid_body_type');

        const emptyBatch = await request({ method: 'POST', path: PATH }, [], validToken);
        test('empty batch returns 400', emptyBatch.statusCode, 400);
        testThat('empty batch names empty_batch in details',
            emptyBatch.body.error.details.some(d => d.code === 'empty_batch'));

        const oversized = await request({ method: 'POST', path: PATH },
            Array.from({ length: 101 }, () => makeRecord()), validToken);
        test('batch over 100 returns 400', oversized.statusCode, 400);
        testThat('oversized batch names batch_too_large in details',
            oversized.body.error.details.some(d => d.code === 'batch_too_large'));

        // --------------------------------------------------------------------
        section('Errors: validation');
        // --------------------------------------------------------------------

        const badVocab = await request({ method: 'POST', path: PATH },
            makeRecord({ purpose: 'world_domination' }), validToken);
        test('unknown purpose returns 400', badVocab.statusCode, 400);
        test('unknown purpose wrapped as validation_failed',
            badVocab.body.error.code, 'validation_failed');
        testThat('details carry the inner invalid_value code',
            badVocab.body.error.details.some(d => d.code === 'invalid_value' && d.field === 'purpose'));

        const badJurisdiction = await request({ method: 'POST', path: PATH },
            makeRecord({ jurisdiction: 'America' }), validToken);
        test('bad jurisdiction returns 400', badJurisdiction.statusCode, 400);
        testThat('details carry invalid_jurisdiction_format',
            badJurisdiction.body.error.details.some(d => d.code === 'invalid_jurisdiction_format'));

        const badTemporal = await request({ method: 'POST', path: PATH },
            makeRecord({ effective_from: daysAgo(1), effective_until: daysAgo(5) }), validToken);
        test('inverted validity window returns 400', badTemporal.statusCode, 400);
        testThat('details carry temporal_invalid',
            badTemporal.body.error.details.some(d => d.code === 'temporal_invalid'));

        const piiBody = await request({ method: 'POST', path: PATH },
            makeRecord({ capture_context: 'signed up as jane@example.com at kiosk' }), validToken);
        test('PII in capture_context returns 400', piiBody.statusCode, 400);
        testThat('details carry pii_detected',
            piiBody.body.error.details.some(d => d.code === 'pii_detected'));
        testThat('response never echoes the PII value',
            !JSON.stringify(piiBody.body).includes('jane@example.com'),
            JSON.stringify(piiBody.body));

        const indexed = await request({ method: 'POST', path: PATH },
            [makeRecord(), makeRecord({ state: 'maybe' })], validToken);
        test('batch validation errors carry the record index',
            indexed.body.error.details[0].index, 1);

        // --------------------------------------------------------------------
        section('Errors: referenced entities (the 404-vs-422 rule)');
        // --------------------------------------------------------------------

        const ghostTenantToken = authHelper.signTestToken(authCtx, { sub: crypto.randomUUID() });
        const ghostTenant = await request({ method: 'POST', path: PATH },
            makeRecord(), ghostTenantToken);
        test('JWT addressing a nonexistent tenant returns 404', ghostTenant.statusCode, 404);
        test('nonexistent tenant has tenant_not_found code',
            ghostTenant.body.error.code, 'tenant_not_found');

        const ghostIdentity = await request({ method: 'POST', path: PATH },
            makeRecord({ identity_id: crypto.randomUUID() }), validToken);
        test('nonexistent identity returns 422', ghostIdentity.statusCode, 422);
        test('nonexistent identity has identity_not_found code',
            ghostIdentity.body.error.code, 'identity_not_found');

        // Tenant scoping (Bible Decision 4): an identity that exists, but in
        // ANOTHER tenant, is indistinguishable from one that doesn't exist.
        const crossTenant = await request({ method: 'POST', path: PATH },
            makeRecord({ identity_id: otherTenantIdentityId }), validToken);
        test('another tenant\'s identity returns 422 (structural isolation)',
            crossTenant.statusCode, 422);

        const rowsSoFar = await query(
            `SELECT COUNT(*)::int AS n FROM consent_records WHERE tenant_id = $1`, [testTenantId]);
        test('no history rows persisted by any rejected request', rowsSoFar.rows[0].n, 0);

        // --------------------------------------------------------------------
        section('Happy path: single record');
        // --------------------------------------------------------------------

        const single = await request({ method: 'POST', path: PATH }, makeRecord(), validToken);
        test('single record returns 201', single.statusCode, 201);
        test('response reports one result', single.body.results.length, 1);
        testThat('result carries a record_id', !!single.body.results[0].record_id);
        test('result reports projection created', single.body.results[0].projection, 'created');
        test('created count is 1', single.body.created, 1);
        test('updated count is 0', single.body.updated, 0);

        const projRow = await query(
            `SELECT state, source_record_id FROM current_consent
             WHERE tenant_id = $1 AND identity_id = $2 AND purpose = 'marketing'
               AND vendor = 'acme_dms' AND channel = 'email'
               AND data_category = 'behavioral' AND jurisdiction = 'US'`,
            [testTenantId, testIdentityId]);
        test('projection row exists with the decision', projRow.rows[0].state, 'granted');
        test('projection sourced from the returned record_id',
            projRow.rows[0].source_record_id, single.body.results[0].record_id);

        // --------------------------------------------------------------------
        section('Happy path: batch with mixed projection outcomes');
        // --------------------------------------------------------------------

        const batch = await request({ method: 'POST', path: PATH }, [
            // supersedes the single record above -> updated
            makeRecord({ state: 'withdrawn', effective_from: daysAgo(2) }),
            // new tuple -> created
            makeRecord({ channel: 'sms', state: 'granted' }),
            // future-dated -> history only, projection 'none'
            makeRecord({ channel: 'push', state: 'granted', effective_from: daysFromNow(7) }),
        ], validToken);
        test('batch returns 201', batch.statusCode, 201);
        test('batch reports three results', batch.body.results.length, 3);
        test('superseding record reports updated', batch.body.results[0].projection, 'updated');
        test('new-tuple record reports created', batch.body.results[1].projection, 'created');
        test('future-dated record reports none', batch.body.results[2].projection, 'none');
        test('created count is 1', batch.body.created, 1);
        test('updated count is 1', batch.body.updated, 1);

        const afterBatch = await query(
            `SELECT state FROM current_consent
             WHERE tenant_id = $1 AND identity_id = $2 AND channel = 'email' AND purpose = 'marketing'`,
            [testTenantId, testIdentityId]);
        test('projection reflects the superseding decision', afterBatch.rows[0].state, 'withdrawn');

        const pushProj = await query(
            `SELECT 1 FROM current_consent
             WHERE tenant_id = $1 AND identity_id = $2 AND channel = 'push'`,
            [testTenantId, testIdentityId]);
        test('future-dated record created no projection row', pushProj.rows.length, 0);

        const historyRows = await query(
            `SELECT COUNT(*)::int AS n FROM consent_records WHERE tenant_id = $1`, [testTenantId]);
        test('all four records entered the history', historyRows.rows[0].n, 4);

        // --------------------------------------------------------------------
        section('Tenant scoping of persisted data');
        // --------------------------------------------------------------------

        const otherRows = await query(
            `SELECT COUNT(*)::int AS n FROM consent_records WHERE tenant_id = $1`, [otherTenantId]);
        test('nothing leaked into the other tenant\'s history', otherRows.rows[0].n, 0);
        const otherProj = await query(
            `SELECT COUNT(*)::int AS n FROM current_consent WHERE tenant_id = $1`, [otherTenantId]);
        test('nothing leaked into the other tenant\'s projection', otherProj.rows[0].n, 0);

        testThat('X-Service header present on responses',
            single.headers['x-service'] === 'threados-core');

        // --------------------------------------------------------------------
        section('GET: auth and validation');
        // --------------------------------------------------------------------

        const getPath = (id, qs = '') => `${PATH}/${id}${qs}`;

        const getNoAuth = await request(
            { method: 'GET', path: getPath(testIdentityId) }, undefined, null);
        test('GET without auth returns 401', getNoAuth.statusCode, 401);

        const getBadUuid = await request(
            { method: 'GET', path: getPath('not-a-uuid') }, undefined, validToken);
        test('GET with malformed identity_id returns 400', getBadUuid.statusCode, 400);
        test('malformed identity_id wrapped as validation_failed',
            getBadUuid.body.error.code, 'validation_failed');
        testThat('details anchor the identity_id field',
            getBadUuid.body.error.details.some(d => d.field === 'identity_id'));

        const getBadInclude = await request(
            { method: 'GET', path: getPath(testIdentityId, '?include=histroy') },
            undefined, validToken);
        test('unknown include value returns 400 (rejected, not ignored)',
            getBadInclude.statusCode, 400);
        testThat('include error is actionable',
            getBadInclude.body.error.details.some(d => d.field === 'include' && d.code === 'invalid_value'));

        const strayLimit = await request(
            { method: 'GET', path: getPath(testIdentityId, '?limit=10') },
            undefined, validToken);
        test('limit without include=history returns 400', strayLimit.statusCode, 400);

        const getBadLimit = await request(
            { method: 'GET', path: getPath(testIdentityId, '?include=history&limit=501') },
            undefined, validToken);
        test('limit over 500 returns 400', getBadLimit.statusCode, 400);
        testThat('limit error carries invalid_value',
            getBadLimit.body.error.details.some(d => d.field === 'limit' && d.code === 'invalid_value'));

        const getBadBefore = await request(
            { method: 'GET', path: getPath(testIdentityId, '?include=history&before=whenever') },
            undefined, validToken);
        test('unparseable before returns 400', getBadBefore.statusCode, 400);

        const getSciLimit = await request(
            { method: 'GET', path: getPath(testIdentityId, '?include=history&limit=1e2') },
            undefined, validToken);
        test('scientific-notation limit returns 400 (canonical digits only)',
            getSciLimit.statusCode, 400);

        // --------------------------------------------------------------------
        section('GET: referenced entities (the 404-vs-422 rule)');
        // --------------------------------------------------------------------

        const getGhostTenant = await request(
            { method: 'GET', path: getPath(testIdentityId) }, undefined, ghostTenantToken);
        test('GET with a nonexistent-tenant JWT returns 404', getGhostTenant.statusCode, 404);
        test('nonexistent tenant has tenant_not_found code',
            getGhostTenant.body.error.code, 'tenant_not_found');

        const getGhostIdentity = await request(
            { method: 'GET', path: getPath(crypto.randomUUID()) }, undefined, validToken);
        test('GET of a nonexistent identity returns 422', getGhostIdentity.statusCode, 422);
        test('nonexistent identity has identity_not_found code',
            getGhostIdentity.body.error.code, 'identity_not_found');

        const getCrossTenant = await request(
            { method: 'GET', path: getPath(otherTenantIdentityId) }, undefined, validToken);
        test('another tenant\'s identity is unreadable via this token (isolation)',
            getCrossTenant.statusCode, 422);

        // --------------------------------------------------------------------
        section('GET: empty state is a 200, not a missing resource');
        // --------------------------------------------------------------------

        const bareIdn = await query(
            `INSERT INTO identities (tenant_id, email_hash, resolution_key, match_source)
             VALUES ($1, $2, $3, 'deterministic') RETURNING id`,
            [testTenantId, '7'.repeat(64), '8'.repeat(64)]
        );
        const bareIdentityId = bareIdn.rows[0].id;

        const emptyGet = await request(
            { method: 'GET', path: getPath(bareIdentityId) }, undefined, validToken);
        test('identity with no consent returns 200', emptyGet.statusCode, 200);
        test('empty state returns an empty consent object', emptyGet.body.consent, {});
        test('identity_id echoed back', emptyGet.body.identity_id, bareIdentityId);
        test('no history key without include=history', emptyGet.body.history, undefined);

        const emptyWithHistory = await request(
            { method: 'GET', path: getPath(bareIdentityId, '?include=history') },
            undefined, validToken);
        test('empty state with include=history returns empty records',
            emptyWithHistory.body.history.records, []);
        test('empty history reports has_more false',
            emptyWithHistory.body.history.has_more, false);

        // --------------------------------------------------------------------
        section('GET: current consent, purpose-grouped');
        // --------------------------------------------------------------------

        // State from the POST tests above: marketing/email withdrawn,
        // marketing/sms granted (push was future-dated - projection untouched).
        const currentGet = await request(
            { method: 'GET', path: getPath(testIdentityId) }, undefined, validToken);
        test('GET current returns 200', currentGet.statusCode, 200);
        test('consent grouped by purpose',
            Object.keys(currentGet.body.consent), ['marketing']);
        test('purpose group carries one entry per remaining dimension tuple',
            currentGet.body.consent.marketing.length, 2);

        const byChannel = Object.fromEntries(
            currentGet.body.consent.marketing.map(e => [e.channel, e]));
        test('email tuple reflects the superseding withdrawal',
            byChannel.email.state, 'withdrawn');
        test('sms tuple reflects its grant', byChannel.sms.state, 'granted');
        testThat('entries carry the full tuple + decision',
            currentGet.body.consent.marketing.every(e =>
                e.vendor && e.channel && e.data_category && e.jurisdiction &&
                e.state && e.consent_basis && e.effective_from && e.source_record_id));
        test('future-dated push tuple absent from current consent',
            byChannel.push, undefined);

        // --------------------------------------------------------------------
        section('GET: history and pagination');
        // --------------------------------------------------------------------

        const withHistory = await request(
            { method: 'GET', path: getPath(testIdentityId, '?include=history') },
            undefined, validToken);
        test('include=history returns the full history', withHistory.body.history.records.length, 4);
        test('full history reports has_more false', withHistory.body.history.has_more, false);
        testThat('history ordered recorded_at DESC',
            withHistory.body.history.records.every((r, i, arr) =>
                i === 0 || arr[i - 1].recorded_at >= r.recorded_at));
        testThat('current consent still present alongside history',
            Object.keys(withHistory.body.consent).length === 1);

        // Pagination against distinct timestamps: three sequential single-record
        // POSTs (separate transactions) give three distinct recorded_at values.
        for (const state of ['granted', 'denied', 'granted']) {
            const page = await request({ method: 'POST', path: PATH },
                makeRecord({ identity_id: bareIdentityId, state }), validToken);
            test(`seed POST for pagination accepted (${state})`, page.statusCode, 201);
        }

        const page1 = await request(
            { method: 'GET', path: getPath(bareIdentityId, '?include=history&limit=2') },
            undefined, validToken);
        test('limit=2 returns two records', page1.body.history.records.length, 2);
        test('truncated page reports has_more true', page1.body.history.has_more, true);

        const cursor = page1.body.history.records[1].recorded_at;
        const page2 = await request(
            { method: 'GET', path: getPath(bareIdentityId, `?include=history&before=${encodeURIComponent(cursor)}`) },
            undefined, validToken);
        test('before cursor returns the remaining record', page2.body.history.records.length, 1);
        test('final page reports has_more false', page2.body.history.has_more, false);
        testThat('pages do not overlap',
            !page1.body.history.records.some(r =>
                r.record_id === page2.body.history.records[0].record_id));

    } catch (err) {
        failed++;
        console.error(`\n${colors.red}Test run aborted:${colors.reset}`, err);
    } finally {
        section('Teardown');
        await teardown();
        console.log(`${colors.green}✓${colors.reset} Cleaned up`);
    }

    console.log(`\n${colors.bold}━━ Summary ━━${colors.reset}`);
    console.log(`${colors.green}Passed:${colors.reset} ${passed}`);
    if (failed > 0) {
        console.log(`${colors.red}Failed:${colors.reset} ${failed}`);
        process.exit(1);
    } else {
        console.log(`${colors.gray}No failures.${colors.reset}`);
    }
}

runTests();

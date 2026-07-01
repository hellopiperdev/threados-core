// ============================================================================
// ThreadOS Core - Consent Recording Logic Tests
// ============================================================================
//
// Exercises src/lib/consent.js. Pure validation logic is tested in memory;
// transaction behavior, projection maintenance, temporal edges, and tenant
// scoping are tested against a real PostgreSQL database.
//
// Tests create temporary test tenants (with recognizable slugs) and clean
// everything up at the end (ON DELETE CASCADE removes identities, consent
// history, and projection rows).
//
// Usage:
//   node tests/lib/consent.test.js
// ============================================================================

require('dotenv').config();

const crypto = require('crypto');
const { query, shutdown } = require('../../src/lib/db');
const {
    MAX_BATCH_SIZE,
    validateConsentRecord,
    validateConsentRequest,
    validateHistoryOptions,
    recordConsent,
    getCurrentConsent,
    getConsentHistory,
    readConsent,
} = require('../../src/lib/consent');

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
// Fixtures
// ----------------------------------------------------------------------------

const TEST_TENANT_SLUG = '_test_tenant_consent_lib';
let tenantId = null;
let otherTenantId = null;
let identityId = null;
let otherTenantIdentityId = null;
let deletedIdentityId = null;

// Relative timestamps so tests never go stale: the "currently in effect"
// window is evaluated against the database clock at run time.
function daysAgo(n) {
    return new Date(Date.now() - n * 24 * 60 * 60 * 1000).toISOString();
}
function daysFromNow(n) {
    return new Date(Date.now() + n * 24 * 60 * 60 * 1000).toISOString();
}

// Build a valid, currently-in-effect consent record, overridable per test.
function makeRecord(overrides = {}) {
    return {
        identity_id: identityId,
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

async function setup() {
    await query(`DELETE FROM tenants WHERE slug IN ($1, $2)`,
        [TEST_TENANT_SLUG, TEST_TENANT_SLUG + '_other']);

    const t = await query(
        `INSERT INTO tenants (slug, display_name, vertical_module)
         VALUES ($1, 'Consent Lib Test Tenant', 'test') RETURNING id`,
        [TEST_TENANT_SLUG]
    );
    tenantId = t.rows[0].id;

    const t2 = await query(
        `INSERT INTO tenants (slug, display_name, vertical_module)
         VALUES ($1, 'Consent Lib Other Tenant', 'test') RETURNING id`,
        [TEST_TENANT_SLUG + '_other']
    );
    otherTenantId = t2.rows[0].id;

    const idn = await query(
        `INSERT INTO identities (tenant_id, email_hash, resolution_key, match_source)
         VALUES ($1, $2, $3, 'deterministic') RETURNING id`,
        [tenantId, 'e'.repeat(64), 'f'.repeat(64)]
    );
    identityId = idn.rows[0].id;

    const otherIdn = await query(
        `INSERT INTO identities (tenant_id, email_hash, resolution_key, match_source)
         VALUES ($1, $2, $3, 'deterministic') RETURNING id`,
        [otherTenantId, 'e'.repeat(64), 'f'.repeat(64)]
    );
    otherTenantIdentityId = otherIdn.rows[0].id;

    const delIdn = await query(
        `INSERT INTO identities (tenant_id, email_hash, resolution_key, match_source, deleted_at)
         VALUES ($1, $2, $3, 'deterministic', CURRENT_TIMESTAMP) RETURNING id`,
        [tenantId, '1'.repeat(64), '2'.repeat(64)]
    );
    deletedIdentityId = delIdn.rows[0].id;
}

async function teardown() {
    try {
        await query(`DELETE FROM tenants WHERE slug IN ($1, $2)`,
            [TEST_TENANT_SLUG, TEST_TENANT_SLUG + '_other']);
    } catch (err) {
        console.log(`${colors.yellow}⚠${colors.reset} Cleanup failed: ${err.message}`);
    }
    await shutdown();
}

async function historyCount(where = {}) {
    const result = await query(
        `SELECT COUNT(*)::int AS n FROM consent_records WHERE tenant_id = $1`,
        [tenantId]
    );
    return result.rows[0].n;
}

async function getProjection(idnId, overrides = {}) {
    const tuple = {
        purpose: 'marketing', vendor: 'acme_dms', channel: 'email',
        data_category: 'behavioral', jurisdiction: 'US', ...overrides,
    };
    const result = await query(
        `SELECT * FROM current_consent
         WHERE tenant_id = $1 AND identity_id = $2 AND purpose = $3 AND vendor = $4
           AND channel = $5 AND data_category = $6 AND jurisdiction = $7`,
        [tenantId, idnId, tuple.purpose, tuple.vendor, tuple.channel,
            tuple.data_category, tuple.jurisdiction]
    );
    return result.rows[0] || null;
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

async function runTests() {
    console.log(`${colors.bold}ThreadOS Core - Consent Recording Logic Tests${colors.reset}`);

    try {
        section('Setup');
        await setup();
        console.log(`${colors.green}✓${colors.reset} Test tenant: ${tenantId}`);

        // --------------------------------------------------------------------
        section('validateConsentRecord: shape and vocabulary');
        // --------------------------------------------------------------------

        const validRecord = validateConsentRecord(makeRecord());
        test('valid record passes', validRecord.valid, true);

        test('non-object record rejected',
            validateConsentRecord('granted').errors[0].code, 'invalid_type');
        test('array-as-record rejected',
            validateConsentRecord([makeRecord()]).errors[0].code, 'invalid_type');

        test('missing identity_id rejected',
            validateConsentRecord(makeRecord({ identity_id: undefined })).errors[0].code, 'missing');
        test('malformed identity_id rejected',
            validateConsentRecord(makeRecord({ identity_id: 'not-a-uuid' })).errors[0].code, 'invalid_format');

        for (const field of ['purpose', 'channel', 'data_category', 'state', 'consent_basis', 'captured_via']) {
            const bad = validateConsentRecord(makeRecord({ [field]: 'not_in_vocabulary' }));
            test(`unknown ${field} rejected with invalid_value`,
                bad.errors[0] && bad.errors[0].code, 'invalid_value');
            testThat(`unknown ${field} error lists allowed values`,
                bad.errors[0].message.includes('must be one of'),
                bad.errors[0].message);
        }

        test('missing vendor rejected',
            validateConsentRecord(makeRecord({ vendor: undefined })).errors[0].code, 'missing');
        test('vendor over 200 chars rejected',
            validateConsentRecord(makeRecord({ vendor: 'v'.repeat(201) })).errors[0].code, 'too_long');

        // --------------------------------------------------------------------
        section('validateConsentRecord: jurisdiction format (ISO 3166)');
        // --------------------------------------------------------------------

        test('country code accepted',
            validateConsentRecord(makeRecord({ jurisdiction: 'DE' })).valid, true);
        test('country-subdivision accepted',
            validateConsentRecord(makeRecord({ jurisdiction: 'US-CA' })).valid, true);
        test('lowercase input normalized to uppercase',
            validateConsentRecord(makeRecord({ jurisdiction: 'us-ca' })).value.jurisdiction, 'US-CA');
        test('three-letter code rejected',
            validateConsentRecord(makeRecord({ jurisdiction: 'USA' })).errors[0].code,
            'invalid_jurisdiction_format');
        test('single letter rejected',
            validateConsentRecord(makeRecord({ jurisdiction: 'U' })).errors[0].code,
            'invalid_jurisdiction_format');
        test('oversized subdivision rejected',
            validateConsentRecord(makeRecord({ jurisdiction: 'US-CAAAA' })).errors[0].code,
            'invalid_jurisdiction_format');
        test('non-string jurisdiction rejected',
            validateConsentRecord(makeRecord({ jurisdiction: 840 })).errors[0].code, 'invalid_type');
        test('missing jurisdiction rejected',
            validateConsentRecord(makeRecord({ jurisdiction: undefined })).errors[0].code, 'missing');

        // --------------------------------------------------------------------
        section('validateConsentRecord: free text and PII');
        // --------------------------------------------------------------------

        test('missing capture_context rejected',
            validateConsentRecord(makeRecord({ capture_context: undefined })).errors[0].code, 'missing');
        test('capture_context over 2000 chars rejected',
            validateConsentRecord(makeRecord({ capture_context: 'x'.repeat(2001) })).errors[0].code, 'too_long');

        const piiContext = validateConsentRecord(
            makeRecord({ capture_context: 'customer replied YES from jane@example.com' }));
        test('PII in capture_context rejected', piiContext.errors[0].code, 'pii_detected');
        test('PII error anchored to the field', piiContext.errors[0].field, 'capture_context');
        testThat('PII error never echoes the value',
            !JSON.stringify(piiContext.errors).includes('jane@example.com'),
            JSON.stringify(piiContext.errors));

        const piiReason = validateConsentRecord(
            makeRecord({ reason: 'customer called from 555-123-4567 to opt out' }));
        test('PII in reason rejected', piiReason.errors[0].code, 'pii_detected');

        // --------------------------------------------------------------------
        section('validateConsentRecord: temporal validity');
        // --------------------------------------------------------------------

        test('missing effective_from rejected',
            validateConsentRecord(makeRecord({ effective_from: undefined })).errors[0].code, 'missing');
        test('unparseable effective_from rejected',
            validateConsentRecord(makeRecord({ effective_from: 'yesterday-ish' })).errors[0].code, 'invalid_format');
        test('null effective_until accepted (open-ended)',
            validateConsentRecord(makeRecord({ effective_until: null })).valid, true);
        test('unparseable effective_until rejected',
            validateConsentRecord(makeRecord({ effective_until: 'never' })).errors[0].code, 'invalid_format');
        test('effective_until after effective_from accepted',
            validateConsentRecord(makeRecord({
                effective_from: daysAgo(10), effective_until: daysFromNow(10),
            })).valid, true);
        test('effective_until before effective_from rejected as temporal_invalid',
            validateConsentRecord(makeRecord({
                effective_from: daysAgo(1), effective_until: daysAgo(5),
            })).errors[0].code, 'temporal_invalid');
        test('effective_until equal to effective_from rejected (zero-length window)',
            validateConsentRecord(makeRecord({
                effective_from: '2026-06-01T00:00:00.000Z',
                effective_until: '2026-06-01T00:00:00.000Z',
            })).errors[0].code, 'temporal_invalid');
        test('future effective_from is valid at the validation layer',
            validateConsentRecord(makeRecord({ effective_from: daysFromNow(5) })).valid, true);

        // --------------------------------------------------------------------
        section('validateConsentRequest: batch semantics');
        // --------------------------------------------------------------------

        test('single object accepted and wrapped',
            validateConsentRequest(makeRecord()).value.length, 1);
        test('array of records accepted',
            validateConsentRequest([makeRecord(), makeRecord({ channel: 'sms' })]).value.length, 2);
        test('empty array rejected',
            validateConsentRequest([]).errors[0].code, 'empty_batch');
        test('bare string body rejected with invalid_body_type',
            validateConsentRequest('granted').code, 'invalid_body_type');
        test('null body rejected with invalid_body_type',
            validateConsentRequest(null).code, 'invalid_body_type');
        test(`batch over ${MAX_BATCH_SIZE} rejected`,
            validateConsentRequest(
                Array.from({ length: MAX_BATCH_SIZE + 1 }, () => makeRecord())
            ).errors[0].code, 'batch_too_large');

        const mixedBatch = validateConsentRequest([
            makeRecord(),
            makeRecord({ purpose: 'bogus' }),
        ]);
        test('reject-all: one bad record rejects the batch', mixedBatch.valid, false);
        test('errors are tagged with the failing record index', mixedBatch.errors[0].index, 1);

        // --------------------------------------------------------------------
        section('recordConsent: tenant and identity gating');
        // --------------------------------------------------------------------

        const ghostTenant = await recordConsent(crypto.randomUUID(), makeRecord());
        test('nonexistent tenant rejected', ghostTenant.code, 'tenant_not_found');

        const ghostIdentity = await recordConsent(tenantId,
            makeRecord({ identity_id: crypto.randomUUID() }));
        test('nonexistent identity rejected', ghostIdentity.code, 'identity_not_found');

        const crossTenant = await recordConsent(tenantId,
            makeRecord({ identity_id: otherTenantIdentityId }));
        test('identity belonging to another tenant rejected (structural isolation)',
            crossTenant.code, 'identity_not_found');

        const softDeleted = await recordConsent(tenantId,
            makeRecord({ identity_id: deletedIdentityId }));
        test('soft-deleted identity rejected', softDeleted.code, 'identity_not_found');

        test('no history rows written by rejected requests', await historyCount(), 0);

        // --------------------------------------------------------------------
        section('recordConsent: history + projection, single record');
        // --------------------------------------------------------------------

        const first = await recordConsent(tenantId, makeRecord());
        test('recording succeeds', first.ok, true);
        test('result reports projection created', first.results[0].projection, 'created');
        test('created count is 1', first.created, 1);
        test('updated count is 0', first.updated, 0);

        const historyRow = await query(
            `SELECT * FROM consent_records WHERE record_id = $1`, [first.results[0].record_id]);
        test('history row persisted', historyRow.rows.length, 1);
        test('history row carries the state', historyRow.rows[0].state, 'granted');

        let projection = await getProjection(identityId);
        testThat('projection row exists', projection !== null);
        test('projection reflects the decision', projection.state, 'granted');
        test('projection points at the source history row',
            projection.source_record_id, first.results[0].record_id);

        // --------------------------------------------------------------------
        section('recordConsent: supersession updates the projection');
        // --------------------------------------------------------------------

        const superseding = await recordConsent(tenantId,
            makeRecord({ state: 'withdrawn', effective_from: daysAgo(2) }));
        test('superseding record reports projection updated',
            superseding.results[0].projection, 'updated');
        test('updated count is 1', superseding.updated, 1);

        projection = await getProjection(identityId);
        test('projection now reflects the withdrawal', projection.state, 'withdrawn');
        test('projection source updated to the new history row',
            projection.source_record_id, superseding.results[0].record_id);
        test('history keeps both rows (append-only)', await historyCount(), 2);

        // --------------------------------------------------------------------
        section('recordConsent: temporal edges skip the projection');
        // --------------------------------------------------------------------

        const futureDated = await recordConsent(tenantId,
            makeRecord({ state: 'denied', effective_from: daysFromNow(5) }));
        test('future-dated record recorded but projection untouched',
            futureDated.results[0].projection, 'none');
        test('future-dated record counts in neither created nor updated',
            futureDated.created + futureDated.updated, 0);
        projection = await getProjection(identityId);
        test('projection still shows the in-effect decision', projection.state, 'withdrawn');

        const expired = await recordConsent(tenantId, makeRecord({
            state: 'granted', effective_from: daysAgo(30), effective_until: daysAgo(20),
        }));
        test('already-expired record recorded but projection untouched',
            expired.results[0].projection, 'none');
        projection = await getProjection(identityId);
        test('projection unaffected by the expired record', projection.state, 'withdrawn');

        test('temporal-edge records still entered the history', await historyCount(), 4);

        const boundedCurrent = await recordConsent(tenantId, makeRecord({
            state: 'granted', effective_from: daysAgo(1), effective_until: daysFromNow(30),
        }));
        test('bounded record whose window covers now hits the projection',
            boundedCurrent.results[0].projection, 'updated');

        // --------------------------------------------------------------------
        section('recordConsent: out-of-order arrivals cannot regress the projection');
        // --------------------------------------------------------------------

        // Projection currently holds effective_from = daysAgo(1). A
        // late-arriving record for an OLDER decision (still technically "in
        // effect" by its own window) must land in history WITHOUT overwriting
        // the newer projected decision.
        const lateArrival = await recordConsent(tenantId,
            makeRecord({ state: 'denied', effective_from: daysAgo(15) }));
        test('older decision arriving late does not touch the projection',
            lateArrival.results[0].projection, 'none');
        projection = await getProjection(identityId);
        test('projection still reflects the newest decision', projection.state, 'granted');
        test('the late arrival is in the history nonetheless', await historyCount(), 6);

        // --------------------------------------------------------------------
        section('recordConsent: intra-batch ordering');
        // --------------------------------------------------------------------

        // The brief's named test: a batch is a sequence of decisions applied
        // in array order.
        const sequenceBatch = await recordConsent(tenantId, [
            makeRecord({ channel: 'sms', state: 'granted', effective_from: daysAgo(5) }),
            makeRecord({ channel: 'sms', state: 'denied', effective_from: daysAgo(3) }),
        ]);
        test('batch with two records for same dimension tuple → projection reflects the later record',
            (await getProjection(identityId, { channel: 'sms' })).state, 'denied');
        test('first record of the pair created the projection row',
            sequenceBatch.results[0].projection, 'created');
        test('second record of the pair superseded it', sequenceBatch.results[1].projection, 'updated');
        test('both records of the pair entered the history', await historyCount(), 8);

        // --------------------------------------------------------------------
        section('recordConsent: distinct tuples project independently');
        // --------------------------------------------------------------------

        const multiTuple = await recordConsent(tenantId, [
            makeRecord({ purpose: 'analytics', state: 'granted' }),
            makeRecord({ purpose: 'analytics', channel: 'push', state: 'denied' }),
        ]);
        test('distinct tuples each create their own projection row', multiTuple.created, 2);
        test('analytics/email tuple projected independently',
            (await getProjection(identityId, { purpose: 'analytics' })).state, 'granted');
        test('analytics/push tuple projected independently',
            (await getProjection(identityId, { purpose: 'analytics', channel: 'push' })).state, 'denied');

        // --------------------------------------------------------------------
        section('recordConsent: batch atomicity (reject-all)');
        // --------------------------------------------------------------------

        const before = await historyCount();
        const partial = await recordConsent(tenantId, [
            makeRecord({ state: 'denied' }),
            makeRecord({ identity_id: crypto.randomUUID() }),
        ]);
        test('batch with one unknown identity is rejected', partial.code, 'identity_not_found');
        test('rejected batch persisted nothing (atomic)', await historyCount(), before);
        projection = await getProjection(identityId);
        test('rejected batch left the projection untouched', projection.state, 'granted');

        const invalidBatch = await recordConsent(tenantId, [
            makeRecord(),
            makeRecord({ purpose: 'bogus' }),
        ]);
        test('validation failure short-circuits with validation_failed',
            invalidBatch.code, 'validation_failed');
        test('validation failure persisted nothing', await historyCount(), before);

        // --------------------------------------------------------------------
        section('validateHistoryOptions: pagination parameters');
        // --------------------------------------------------------------------

        const defaults = validateHistoryOptions({});
        test('defaults: limit 100', defaults.value.limit, 100);
        test('defaults: before null', defaults.value.before, null);

        test('numeric-string limit accepted (query params arrive as strings)',
            validateHistoryOptions({ limit: '50' }).value.limit, 50);
        test('limit at the max accepted',
            validateHistoryOptions({ limit: '500' }).value.limit, 500);
        test('limit over the max rejected, not clamped',
            validateHistoryOptions({ limit: '501' }).errors[0].code, 'invalid_value');
        test('limit zero rejected',
            validateHistoryOptions({ limit: '0' }).errors[0].code, 'invalid_value');
        test('non-integer limit rejected',
            validateHistoryOptions({ limit: '2.5' }).errors[0].code, 'invalid_format');
        test('non-numeric limit rejected',
            validateHistoryOptions({ limit: 'lots' }).errors[0].code, 'invalid_format');
        test('repeated limit param (array) rejected',
            validateHistoryOptions({ limit: ['5', '10'] }).errors[0].code, 'invalid_format');

        test('valid before normalized to canonical ISO',
            validateHistoryOptions({ before: '2026-06-01T00:00:00Z' }).value.before,
            '2026-06-01T00:00:00.000Z');
        test('unparseable before rejected',
            validateHistoryOptions({ before: 'last tuesday' }).errors[0].code, 'invalid_format');
        test('bad limit and bad before both reported',
            validateHistoryOptions({ limit: 'x', before: 'y' }).errors.length, 2);

        // A consent-free identity for empty-state reads.
        const readIdn = await query(
            `INSERT INTO identities (tenant_id, email_hash, resolution_key, match_source)
             VALUES ($1, $2, $3, 'deterministic') RETURNING id`,
            [tenantId, '5'.repeat(64), '6'.repeat(64)]
        );
        const readIdentityId = readIdn.rows[0].id;

        // --------------------------------------------------------------------
        section('getCurrentConsent: projection reads');
        // --------------------------------------------------------------------

        test('identity with no consent reads as empty (no consent, not an error)',
            await getCurrentConsent(tenantId, readIdentityId), []);

        // State accumulated above: marketing/email (granted), marketing/sms
        // (denied), analytics/email (granted), analytics/push (denied).
        const currentRows = await getCurrentConsent(tenantId, identityId);
        test('all currently-effective tuples returned', currentRows.length, 4);
        test('rows come back in deterministic dimension order (purpose first)',
            currentRows.map(r => `${r.purpose}/${r.channel}`),
            ['analytics/email', 'analytics/push', 'marketing/email', 'marketing/sms']);
        testThat('rows carry the full decision (state, basis, effective_from, source)',
            currentRows.every(r => r.state && r.consent_basis && r.effective_from && r.source_record_id));

        test('projection read is tenant-scoped: other tenant sees nothing',
            await getCurrentConsent(otherTenantId, identityId), []);

        // --------------------------------------------------------------------
        section('getConsentHistory: ordering and pagination');
        // --------------------------------------------------------------------

        const fullHistory = await getConsentHistory(tenantId, identityId);
        test('full history returned under the default limit', fullHistory.records.length, 10);
        test('full history reports has_more false', fullHistory.has_more, false);
        testThat('history is ordered recorded_at DESC',
            fullHistory.records.every((r, i, arr) =>
                i === 0 || arr[i - 1].recorded_at >= r.recorded_at));
        testThat('history rows carry the full record (context, reason, valid time)',
            fullHistory.records.every(r =>
                r.record_id && r.capture_context && r.reason && r.effective_from !== undefined));

        const limited = await getConsentHistory(tenantId, identityId, { limit: 3 });
        test('limit truncates the page', limited.records.length, 3);
        test('truncated page reports has_more true', limited.has_more, true);

        // Keyset pagination: everything strictly before the newest timestamp.
        // The two newest rows (the multi-tuple batch) share one recorded_at, so
        // this also exercises the exclusive cursor against a timestamp tie.
        const newestTs = fullHistory.records[0].recorded_at;
        const olderPage = await getConsentHistory(tenantId, identityId,
            { before: newestTs.toISOString() });
        test('before cursor excludes the cursor timestamp (exclusive)',
            olderPage.records.length, 8);
        testThat('paged records do not overlap the newer ones',
            olderPage.records.every(r => r.recorded_at < newestTs));

        test('history read is tenant-scoped: other tenant sees nothing',
            (await getConsentHistory(otherTenantId, identityId)).records, []);
        test('empty history for a consent-free identity',
            (await getConsentHistory(tenantId, readIdentityId)).records, []);

        // --------------------------------------------------------------------
        section('readConsent: orchestration');
        // --------------------------------------------------------------------

        test('nonexistent tenant rejected on read',
            (await readConsent(crypto.randomUUID(), identityId)).code, 'tenant_not_found');
        test('nonexistent identity rejected on read',
            (await readConsent(tenantId, crypto.randomUUID())).code, 'identity_not_found');
        test('another tenant\'s identity rejected on read (structural isolation)',
            (await readConsent(tenantId, otherTenantIdentityId)).code, 'identity_not_found');
        test('soft-deleted identity rejected on read',
            (await readConsent(tenantId, deletedIdentityId)).code, 'identity_not_found');

        const emptyRead = await readConsent(tenantId, readIdentityId);
        test('existing identity with no consent reads ok', emptyRead.ok, true);
        test('empty read returns an empty current set', emptyRead.current, []);
        test('history omitted unless requested', emptyRead.history, undefined);

        const fullRead = await readConsent(tenantId, identityId, { includeHistory: true, limit: 3 });
        test('read returns the current projection', fullRead.current.length, 4);
        test('read honors the history limit', fullRead.history.records.length, 3);
        test('read reports has_more for the truncated history', fullRead.history.has_more, true);

        // --------------------------------------------------------------------
        section('Clock boundaries: expiry and future windows (Session 5, HIGH-1)');
        // --------------------------------------------------------------------

        const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
        const secondsFromNow = (s) => new Date(Date.now() + s * 1000).toISOString();

        const mkClockIdentity = async (seed) => {
            const res = await query(
                `INSERT INTO identities (tenant_id, email_hash, resolution_key, match_source)
                 VALUES ($1, $2, $3, 'deterministic') RETURNING id`,
                [tenantId, seed.repeat(32), seed.repeat(32).split('').reverse().join('')]
            );
            return res.rows[0].id;
        };

        // Expiring grant: valid at write time, lapses 1.5s later.
        const expIdn = await mkClockIdentity('e5');
        const expiring = await recordConsent(tenantId,
            makeRecord({ identity_id: expIdn, effective_from: daysAgo(1), effective_until: secondsFromNow(1.5) }));
        test('bounded grant valid now enters the projection',
            expiring.results[0].projection, 'created');
        const beforeExpiry = await getCurrentConsent(tenantId, expIdn);
        test('bounded grant visible before expiry', beforeExpiry.length, 1);
        testThat('read row carries its window end', beforeExpiry[0].effective_until !== null);

        await sleep(2000);
        test('expired grant is INVISIBLE the moment its window lapses',
            await getCurrentConsent(tenantId, expIdn), []);

        // Future-dated grant: never enters the projection; stays invisible
        // even to reads (the documented future-activation position - live
        // activation requires the window to have started at write time).
        const futIdn = await mkClockIdentity('f5');
        const future = await recordConsent(tenantId,
            makeRecord({ identity_id: futIdn, effective_from: secondsFromNow(60) }));
        test('future-dated grant stays history-only', future.results[0].projection, 'none');
        test('future-dated grant invisible to current reads',
            await getCurrentConsent(tenantId, futIdn), []);

        // Expired incumbent holds no supersession rights: a currently-valid
        // record with an EARLIER effective_from must be able to replace a
        // lapsed row (guard arm 2) - an expired row is semantically "no row".
        const vacIdn = await mkClockIdentity('a7');
        await recordConsent(tenantId, makeRecord({
            identity_id: vacIdn, effective_from: daysAgo(1), effective_until: secondsFromNow(1.5),
        }));
        await sleep(2000);
        test('lapsed incumbent invisible', await getCurrentConsent(tenantId, vacIdn), []);
        const revival = await recordConsent(tenantId, makeRecord({
            identity_id: vacIdn, state: 'granted', effective_from: daysAgo(5), effective_until: null,
        }));
        test('currently-valid backdated record replaces the lapsed incumbent',
            revival.results[0].projection, 'updated');
        const revived = await getCurrentConsent(tenantId, vacIdn);
        test('projection shows the reviving record', revived.length, 1);
        test('reviving record is the visible decision', revived[0].state, 'granted');

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

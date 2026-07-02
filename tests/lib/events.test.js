// ============================================================================
// ThreadOS Core - Event Capture Logic Tests
// ============================================================================
//
// Exercises src/lib/events.js. Pure validation/PII logic is tested in memory;
// registry, identity, persistence, and idempotency behavior is tested against
// a real PostgreSQL database.
//
// Tests create a temporary test tenant (with a recognizable slug), seed a few
// baseline event types into event_type_registry, and clean everything up at
// the end (ON DELETE CASCADE removes seeded registry rows and events).
//
// Usage:
//   node tests/lib/events.test.js
// ============================================================================

require('dotenv').config();

const crypto = require('crypto');
const { query, withTransaction, shutdown } = require('../../src/lib/db');
const {
    scanForPii,
    detectPiiInScalar,
    validateEvent,
    validateEventsRequest,
    checkRegistry,
    checkIdentities,
    captureEvents: captureEventsRaw,
    MAX_BATCH_SIZE,
} = require('../../src/lib/events');
const { recordConsent: recordConsentRaw } = require('../../src/lib/consent');

// Step 8: every compliance write carries an actor for the audit trail.
const TEST_ACTOR = '_test_events_lib';
const captureEvents = (t, b, actor = TEST_ACTOR) => captureEventsRaw(t, b, actor);
const recordConsent = (t, b, actor = TEST_ACTOR) => recordConsentRaw(t, b, actor);

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

const TEST_TENANT_SLUG = '_test_tenant_events_lib';
let tenantId = null;
let otherTenantId = null;
let identityId = null;

// Baseline event types seeded for testing (registered for the test tenant).
const SEED_EVENT_TYPES = [
    { event_name: 'page_viewed', event_category: 'engagement' },
    { event_name: 'form_submitted', event_category: 'conversion' },
    { event_name: 'purchase_completed', event_category: 'commerce' },
];

// Build a valid event object, overridable per test.
function makeEvent(overrides = {}) {
    return {
        event_id: crypto.randomUUID(),
        event_name: 'page_viewed',
        event_category: 'engagement',
        source_type: 'web',
        event_timestamp: '2026-06-26T12:00:00.000Z',
        session_id: crypto.randomUUID(),
        properties: { path: '/home', referrer: 'google' },
        ...overrides,
    };
}

// --- Consent-enforcement helpers (Step 7 Session 4) -------------------------

// Mint a fresh identity so each enforcement scenario starts with a clean
// consent slate.
async function mkIdentity() {
    const hash = crypto.randomBytes(32).toString('hex');
    const key = crypto.randomBytes(32).toString('hex');
    const res = await query(
        `INSERT INTO identities (tenant_id, email_hash, resolution_key, match_source)
         VALUES ($1, $2, $3, 'deterministic') RETURNING id`,
        [tenantId, hash, key]
    );
    return res.rows[0].id;
}

// Record a consent decision through the real write path (Session 2), so the
// current_consent projection enforcement reads is maintained for real.
async function seedConsent(idnId, overrides = {}) {
    const result = await recordConsent(tenantId, {
        identity_id: idnId,
        purpose: 'analytics',
        vendor: 'acme_dms',
        channel: 'in_app',
        data_category: 'behavioral',
        jurisdiction: 'US',
        state: 'granted',
        consent_basis: 'active_consent',
        captured_via: 'web_form',
        capture_context: 'Seeded by events enforcement tests',
        reason: 'Test fixture consent decision',
        effective_from: new Date(Date.now() - 86400000).toISOString(),
        effective_until: null,
        ...overrides,
    });
    if (!result.ok) {
        throw new Error(`seedConsent failed: ${JSON.stringify(result.errors)}`);
    }
    return result;
}

async function setPosture(posture) {
    await query(`UPDATE tenants SET compliance_posture = $1 WHERE id = $2`, [posture, tenantId]);
}

async function setup() {
    await query(`DELETE FROM tenants WHERE slug IN ($1, $2)`,
        [TEST_TENANT_SLUG, TEST_TENANT_SLUG + '_other']);

    const t = await query(
        `INSERT INTO tenants (slug, display_name, vertical_module)
         VALUES ($1, 'Events Lib Test Tenant', 'test') RETURNING id`,
        [TEST_TENANT_SLUG]
    );
    tenantId = t.rows[0].id;

    const t2 = await query(
        `INSERT INTO tenants (slug, display_name, vertical_module)
         VALUES ($1, 'Events Lib Other Tenant', 'test') RETURNING id`,
        [TEST_TENANT_SLUG + '_other']
    );
    otherTenantId = t2.rows[0].id;

    // Seed baseline event types for the test tenant.
    for (const et of SEED_EVENT_TYPES) {
        await query(
            `INSERT INTO event_type_registry (tenant_id, event_name, event_category)
             VALUES ($1, $2, $3)
             ON CONFLICT (tenant_id, event_name) DO NOTHING`,
            [tenantId, et.event_name, et.event_category]
        );
    }

    // An identity to reference in identity_id tests.
    const idn = await query(
        `INSERT INTO identities (tenant_id, email_hash, resolution_key, match_source)
         VALUES ($1, $2, $3, 'deterministic') RETURNING id`,
        [tenantId, 'a'.repeat(64), 'b'.repeat(64)]
    );
    identityId = idn.rows[0].id;
}

async function teardown() {
    // audit_log has no FKs (by design) - clean test audit rows explicitly.
    await query(`DELETE FROM audit_log WHERE tenant_id = ANY($1)`,
        [[tenantId, otherTenantId].filter(Boolean)]);
    await query(`DELETE FROM tenants WHERE slug IN ($1, $2)`,
        [TEST_TENANT_SLUG, TEST_TENANT_SLUG + '_other']);
    await shutdown();
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

async function runTests() {
    console.log(`${colors.bold}ThreadOS Core - Event Capture Logic Tests${colors.reset}`);

    try {
        section('Setup');
        await setup();
        console.log(`${colors.green}✓${colors.reset} Test tenant: ${tenantId}`);
        console.log(`${colors.green}✓${colors.reset} Seeded ${SEED_EVENT_TYPES.length} event types, 1 identity`);

        // --------------------------------------------------------------------
        section('PII detection (Decision 10)');
        // --------------------------------------------------------------------

        test('detects email in scalar', detectPiiInScalar('jane@example.com'), 'email');
        test('detects SSN in scalar', detectPiiInScalar('123-45-6789'), 'ssn');
        test('detects formatted phone in scalar', detectPiiInScalar('555-123-4567'), 'phone');
        test('detects phone with +1 country code', detectPiiInScalar('+1 (555) 123-4567'), 'phone');
        test('detects parenthesized area code', detectPiiInScalar('(555) 123-4567'), 'phone');

        // International phone formats (Gap 2). These all slipped through the
        // US-only regex; the new international pattern catches the +CC grouping.
        test('detects UK international phone', detectPiiInScalar('+44 20 7946 0958'), 'phone');
        test('detects China international phone', detectPiiInScalar('+86 138 0000 0000'), 'phone');
        test('detects Germany international phone', detectPiiInScalar('+49 30 12345678'), 'phone');
        // Unseparated E.164: a + prefix plus 8-15 digits, no separators. Once a +
        // is present, a long digit run is a phone, not an order number.
        test('detects UK unseparated E.164', detectPiiInScalar('+442079460958'), 'phone');
        test('detects China unseparated E.164', detectPiiInScalar('+8613800000000'), 'phone');
        // Under-detection guard: the international patterns must not fire on a bare
        // country code, a +-prefixed run too short to be a real number, or a + that
        // sits next to a short separated group.
        test('bare +1 is NOT flagged', detectPiiInScalar('+1'), null);
        test('+12345 is too short to be flagged', detectPiiInScalar('+12345'), null);
        test('plus-tagged short token is NOT flagged', detectPiiInScalar('order+12 34'), null);
        // Narrowing: a bare run of 10 digits is NOT treated as a phone (could be
        // an order number / id). We under-detect on purpose.
        test('bare 10-digit number is NOT flagged as phone', detectPiiInScalar('5551234567'), null);
        test('clean string is not flagged', detectPiiInScalar('hello world'), null);
        test('short number is not flagged', detectPiiInScalar(42), null);
        test('boolean is not scanned', detectPiiInScalar(true), null);

        const nested = scanForPii({ contact: { email: 'a@b.co' }, ok: 'fine' });
        test('nested email found, one finding', nested.length, 1);
        test('nested email path', nested[0].path, 'properties.contact.email');
        test('nested email type', nested[0].type, 'email');

        const inArray = scanForPii({ tags: ['fine', 'call 555-123-4567'] });
        test('array element PII path', inArray[0] && inArray[0].path, 'properties.tags[1]');

        // A formatted phone embedded in a string value is caught regardless of key.
        const formattedPhoneValue = scanForPii({ note: 'reach me at 555.123.4567' });
        test('formatted phone in a value is flagged', formattedPhoneValue.length, 1);
        test('formatted phone reported as phone type', formattedPhoneValue[0].type, 'phone');

        // A bare numeric value is not flagged (under-detection bias).
        const bareNumericValue = scanForPii({ order_number: 5551234567 });
        test('bare numeric value is not flagged', bareNumericValue.length, 0);

        test('clean properties yields no findings', scanForPii({ a: 1, b: 'x', c: true }).length, 0);

        // PII in object KEYS, not just values (Gap 1). {"jane@example.com": "x"}
        // would previously persist the email; now the key itself is scanned.
        const emailKey = scanForPii({ 'jane@example.com': 'clicked' });
        testThat('email in an object key is flagged',
            emailKey.some(f => f.type === 'email'));
        testThat('key finding path marks it as a key (distinct from a value path)',
            emailKey.some(f => f.type === 'email' && f.path.includes('[key#')));
        testThat('the PII key text is NOT echoed in the finding path',
            !emailKey.some(f => f.path.includes('jane@example.com')));

        const phoneKey = scanForPii({ '+44 20 7946 0958': 'ok' });
        testThat('international phone in an object key is flagged',
            phoneKey.some(f => f.type === 'phone'));

        const nestedKey = scanForPii({ contact: { 'a@b.co': 'x' } });
        testThat('PII in a nested key is flagged at the nested path',
            nestedKey.some(f => f.type === 'email' && f.path.startsWith('properties.contact[key#')));

        // A clean key whose VALUE is PII is still reported as a value finding (no
        // [key# marker) - proves the two cases stay distinguishable.
        const valuePii = scanForPii({ note: 'reach me at 555-123-4567' });
        testThat('PII value under a clean key is reported as a value, not a key',
            valuePii.length === 1 && !valuePii[0].path.includes('[key#'));

        // Over-detection guard for keys: an ordinary key is not flagged.
        test('ordinary keys are not flagged', scanForPii({ user_id: 'abc', count: 3 }).length, 0);

        // --------------------------------------------------------------------
        section('validateEvent (Decisions 7, 8)');
        // --------------------------------------------------------------------

        test('valid event passes', validateEvent(makeEvent()).valid, true);

        const noId = validateEvent(makeEvent({ event_id: undefined }));
        testThat('missing event_id rejected', !noId.valid &&
            noId.errors.some(e => e.field === 'event_id' && e.code === 'missing'));

        const badId = validateEvent(makeEvent({ event_id: 'not-a-uuid' }));
        testThat('non-UUID event_id rejected', !badId.valid &&
            badId.errors.some(e => e.field === 'event_id' && e.code === 'invalid_format'));

        const noName = validateEvent(makeEvent({ event_name: undefined }));
        testThat('missing event_name rejected', !noName.valid &&
            noName.errors.some(e => e.field === 'event_name'));

        const emptyName = validateEvent(makeEvent({ event_name: '   ' }));
        testThat('blank event_name rejected', !emptyName.valid &&
            emptyName.errors.some(e => e.field === 'event_name'));

        const noCategory = validateEvent(makeEvent({ event_category: undefined }));
        testThat('missing event_category rejected', !noCategory.valid &&
            noCategory.errors.some(e => e.field === 'event_category'));

        const noSource = validateEvent(makeEvent({ source_type: undefined }));
        testThat('missing source_type rejected', !noSource.valid &&
            noSource.errors.some(e => e.field === 'source_type'));

        const badTs = validateEvent(makeEvent({ event_timestamp: 'not-a-date' }));
        testThat('invalid event_timestamp rejected', !badTs.valid &&
            badTs.errors.some(e => e.field === 'event_timestamp' && e.code === 'invalid_format'));

        const tsNormalized = validateEvent(makeEvent({ event_timestamp: '2026-06-26T12:00:00Z' }));
        test('event_timestamp normalized to ISO', tsNormalized.value.event_timestamp, '2026-06-26T12:00:00.000Z');

        // Identifier rules: at least one of identity_id / session_id / device_fingerprint
        const noIdentifier = validateEvent(makeEvent({ session_id: undefined }));
        testThat('no identifier rejected', !noIdentifier.valid &&
            noIdentifier.errors.some(e => e.code === 'missing_identifier'));

        test('session_id only is valid',
            validateEvent(makeEvent({ session_id: crypto.randomUUID() })).valid, true);
        test('device_fingerprint only is valid',
            validateEvent(makeEvent({ session_id: undefined, device_fingerprint: 'fp-abc-123' })).valid, true);
        test('identity_id only is valid',
            validateEvent(makeEvent({ session_id: undefined, identity_id: crypto.randomUUID() })).valid, true);

        // session_id is opaque: Core does not own its format, so a non-UUID
        // string (Express/Rails/SDK session IDs are not UUIDs) must be accepted.
        const opaqueSession = validateEvent(makeEvent({ session_id: 'sess_aBc123.XYZ-opaque' }));
        test('non-UUID (opaque) session_id is valid', opaqueSession.valid, true);
        test('opaque session_id preserved as-is',
            opaqueSession.value.session_id, 'sess_aBc123.XYZ-opaque');

        const ctrlSession = validateEvent(makeEvent({ session_id: 'sess\x00bad' }));
        testThat('session_id with control character rejected', !ctrlSession.valid &&
            ctrlSession.errors.some(e => e.field === 'session_id' && e.code === 'invalid_characters'));

        const ctrlFingerprint = validateEvent(makeEvent({ session_id: undefined, device_fingerprint: 'fp\x07bad' }));
        testThat('device_fingerprint with control character rejected', !ctrlFingerprint.valid &&
            ctrlFingerprint.errors.some(e => e.field === 'device_fingerprint' && e.code === 'invalid_characters'));

        const opaqueFingerprint = validateEvent(makeEvent({ session_id: undefined, device_fingerprint: 'fp-abc-123' }));
        test('opaque device_fingerprint is valid', opaqueFingerprint.valid, true);

        const piiEvt = validateEvent(makeEvent({ properties: { email: 'jane@example.com' } }));
        testThat('PII in properties rejected', !piiEvt.valid &&
            piiEvt.errors.some(e => e.code === 'pii_detected'));

        const badProps = validateEvent(makeEvent({ properties: [1, 2, 3] }));
        testThat('array properties rejected', !badProps.valid &&
            badProps.errors.some(e => e.field === 'properties' && e.code === 'invalid_type'));

        test('absent properties defaults to empty object',
            validateEvent(makeEvent({ properties: undefined })).value.properties, {});

        // --------------------------------------------------------------------
        section('validateEventsRequest (batch, Decision 7)');
        // --------------------------------------------------------------------

        const single = validateEventsRequest(makeEvent());
        testThat('single object normalized to array', single.valid && single.value.length === 1);

        const batch = validateEventsRequest([makeEvent(), makeEvent()]);
        testThat('array of two valid', batch.valid && batch.value.length === 2);

        const emptyArr = validateEventsRequest([]);
        testThat('empty array rejected', !emptyArr.valid &&
            emptyArr.errors.some(e => e.code === 'empty_batch'));

        // A valid-JSON-but-wrong-top-level-type body is rejected with a dedicated
        // invalid_body_type code (not invalid_type / not invalid_json), so the
        // route can tell the client the shape is wrong rather than the bytes.
        const notObj = validateEventsRequest('hello');
        testThat('string body rejected as invalid_body_type', !notObj.valid &&
            notObj.code === 'invalid_body_type' &&
            notObj.errors.some(e => e.code === 'invalid_body_type'));
        testThat('number body rejected as invalid_body_type',
            validateEventsRequest(42).code === 'invalid_body_type');
        testThat('null body rejected as invalid_body_type',
            validateEventsRequest(null).code === 'invalid_body_type');
        testThat('boolean body rejected as invalid_body_type',
            validateEventsRequest(true).code === 'invalid_body_type');

        const mixedBatch = validateEventsRequest([makeEvent(), makeEvent({ event_name: undefined })]);
        testThat('one bad event rejects whole batch', !mixedBatch.valid);
        testThat('batch error carries index of bad event',
            mixedBatch.errors.some(e => e.index === 1 && e.field === 'event_name'));

        const dupeId = crypto.randomUUID();
        const dupBatch = validateEventsRequest([
            makeEvent({ event_id: dupeId }),
            makeEvent({ event_id: dupeId }),
        ]);
        testThat('duplicate event_id in batch rejected', !dupBatch.valid &&
            dupBatch.errors.some(e => e.code === 'duplicate_event_id_in_batch'));

        const tooBig = validateEventsRequest(
            Array.from({ length: MAX_BATCH_SIZE + 1 }, () => makeEvent()));
        testThat('oversized batch rejected', !tooBig.valid &&
            tooBig.errors.some(e => e.code === 'batch_too_large'));

        // --------------------------------------------------------------------
        section('checkRegistry (DB, Decision 8)');
        // --------------------------------------------------------------------

        await withTransaction(async (client) => {
            const ok = await checkRegistry(client, tenantId, [makeEvent()]);
            test('registered event passes registry check', ok.ok, true);

            const unreg = await checkRegistry(client, tenantId,
                [makeEvent({ event_name: 'never_registered' })]);
            testThat('unregistered event rejected', !unreg.ok &&
                unreg.errors.some(e => e.code === 'unregistered_event'));

            const mismatch = await checkRegistry(client, tenantId,
                [makeEvent({ event_name: 'page_viewed', event_category: 'wrong_category' })]);
            testThat('category mismatch rejected', !mismatch.ok &&
                mismatch.errors.some(e => e.code === 'event_category_mismatch'));

            // Registry is tenant-scoped: the other tenant has no registrations.
            const otherTenant = await checkRegistry(client, otherTenantId, [makeEvent()]);
            testThat('registry is tenant-scoped', !otherTenant.ok &&
                otherTenant.errors.some(e => e.code === 'unregistered_event'));
        });

        // --------------------------------------------------------------------
        section('checkIdentities (DB)');
        // --------------------------------------------------------------------

        await withTransaction(async (client) => {
            const ok = await checkIdentities(client, tenantId,
                [makeEvent({ identity_id: identityId })]);
            test('existing identity passes', ok.ok, true);

            const missing = await checkIdentities(client, tenantId,
                [makeEvent({ identity_id: crypto.randomUUID() })]);
            testThat('nonexistent identity rejected', !missing.ok &&
                missing.errors.some(e => e.code === 'identity_not_found'));

            const noIdentity = await checkIdentities(client, tenantId, [makeEvent()]);
            test('event with no identity_id passes', noIdentity.ok, true);

            // Identity belongs to test tenant, not the other tenant.
            const crossTenant = await checkIdentities(client, otherTenantId,
                [makeEvent({ identity_id: identityId })]);
            testThat('identity check is tenant-scoped', !crossTenant.ok);
        });

        // --------------------------------------------------------------------
        section('captureEvents: persistence + idempotency (Decision 17)');
        // --------------------------------------------------------------------

        // The test tenant is strict-posture (the schema default), so an
        // identified capture needs an active-consent grant on the books
        // (Step 7 Session 4: capture is consent-enforced).
        await seedConsent(identityId);

        const evt = makeEvent({ identity_id: identityId });
        const first = await captureEvents(tenantId, evt);
        test('first capture ok', first.ok, true);
        test('first capture created 1', first.created, 1);
        test('first capture status created', first.results[0].status, 'created');
        testThat('created result includes Core id', !!first.results[0].id);

        // Verify it actually persisted with the expected columns.
        const row = await query(
            `SELECT event_id, event_name, identity_id, validation_status,
                    consent_snapshot, session_id, device_fingerprint
             FROM events WHERE tenant_id = $1 AND event_id = $2`,
            [tenantId, evt.event_id]
        );
        test('event persisted exactly once', row.rows.length, 1);
        test('persisted event_name', row.rows[0].event_name, 'page_viewed');
        test('persisted validation_status valid', row.rows[0].validation_status, 'valid');
        testThat('consent_snapshot records the granted evaluation',
            row.rows[0].consent_snapshot && row.rows[0].consent_snapshot.status === 'granted',
            JSON.stringify(row.rows[0].consent_snapshot));
        testThat('snapshot cites posture, purpose, basis, and the authorizing record',
            row.rows[0].consent_snapshot.posture === 'strict' &&
            row.rows[0].consent_snapshot.purpose === 'analytics' &&
            row.rows[0].consent_snapshot.basis === 'active_consent' &&
            !!row.rows[0].consent_snapshot.source_record_id,
            JSON.stringify(row.rows[0].consent_snapshot));

        // Re-submitting the same event_id is a no-op success (idempotency).
        const second = await captureEvents(tenantId, evt);
        test('replay capture ok', second.ok, true);
        test('replay created 0', second.created, 0);
        test('replay duplicates 1', second.duplicates, 1);
        test('replay status duplicate', second.results[0].status, 'duplicate');

        const stillOne = await query(
            `SELECT count(*)::int AS n FROM events WHERE tenant_id = $1 AND event_id = $2`,
            [tenantId, evt.event_id]
        );
        test('replay did not create a second row', stillOne.rows[0].n, 1);

        // Mixed batch: one new + one already-seen → 1 created, 1 duplicate.
        const newEvt = makeEvent();
        const mixed = await captureEvents(tenantId, [newEvt, evt]);
        test('mixed batch ok', mixed.ok, true);
        test('mixed batch created 1', mixed.created, 1);
        test('mixed batch duplicates 1', mixed.duplicates, 1);

        // --------------------------------------------------------------------
        section('captureEvents: rejections are all-or-nothing (Decision 7)');
        // --------------------------------------------------------------------

        const piiCapture = await captureEvents(tenantId,
            makeEvent({ properties: { email: 'jane@example.com' } }));
        testThat('PII capture rejected', !piiCapture.ok && piiCapture.code === 'validation_failed');

        const unregCapture = await captureEvents(tenantId,
            makeEvent({ event_name: 'never_registered' }));
        testThat('unregistered capture rejected', !unregCapture.ok &&
            unregCapture.code === 'unregistered_event');

        // Reject-all: a batch with one unregistered event persists nothing.
        const goodEvt = makeEvent();
        const rejectAll = await captureEvents(tenantId,
            [goodEvt, makeEvent({ event_name: 'never_registered' })]);
        testThat('batch with one bad event rejected', !rejectAll.ok);
        const goodPersisted = await query(
            `SELECT count(*)::int AS n FROM events WHERE tenant_id = $1 AND event_id = $2`,
            [tenantId, goodEvt.event_id]
        );
        test('reject-all persisted nothing from the batch', goodPersisted.rows[0].n, 0);

        const badIdentityCapture = await captureEvents(tenantId,
            makeEvent({ identity_id: crypto.randomUUID() }));
        testThat('nonexistent identity capture rejected', !badIdentityCapture.ok &&
            badIdentityCapture.code === 'identity_not_found');

        const noTenant = await captureEvents('00000000-0000-0000-0000-000000000000', makeEvent());
        testThat('nonexistent tenant rejected', !noTenant.ok && noTenant.code === 'tenant_not_found');

        // --------------------------------------------------------------------
        section('captureEvents: consent enforcement (Decision 15)');
        // --------------------------------------------------------------------

        // Event types with declared purposes (migration 006) for the
        // enforcement scenarios. page_viewed keeps the analytics default.
        await query(
            `INSERT INTO event_type_registry (tenant_id, event_name, event_category, implicated_purpose)
             VALUES ($1, 'order_status_updated', 'operations', 'service_operations'),
                    ($1, 'consent_receipt_issued', 'compliance', 'legal_compliance')
             ON CONFLICT (tenant_id, event_name) DO NOTHING`,
            [tenantId]
        );
        const opsEvent = (idn) => makeEvent({
            event_name: 'order_status_updated', event_category: 'operations', identity_id: idn,
        });
        const complianceEvent = (idn) => makeEvent({
            event_name: 'consent_receipt_issued', event_category: 'compliance', identity_id: idn,
        });
        const analyticsEvent = (idn) => makeEvent({ identity_id: idn });

        // ---- Strict posture (the tenant default) ----
        await setPosture('strict');

        const noRecord = await captureEvents(tenantId, analyticsEvent(await mkIdentity()));
        testThat('strict: no consent record -> consent_denied',
            !noRecord.ok && noRecord.code === 'consent_denied');
        testThat('rejection message names the reason',
            noRecord.errors[0].message.includes('no_consent_record'));
        testThat('rejection message points at the consent read API (diagnostic hint)',
            noRecord.errors[0].message.includes('GET /api/v1/consent/:identity_id'));

        const deniedIdn = await mkIdentity();
        await seedConsent(deniedIdn, { state: 'denied' });
        const denied = await captureEvents(tenantId, analyticsEvent(deniedIdn));
        testThat('strict: denied state -> consent_denied',
            !denied.ok && denied.errors[0].message.includes('consent_denied'));

        const withdrawnIdn = await mkIdentity();
        await seedConsent(withdrawnIdn, { state: 'withdrawn' });
        const withdrawn = await captureEvents(tenantId, analyticsEvent(withdrawnIdn));
        testThat('strict: withdrawn state -> consent_denied',
            !withdrawn.ok && withdrawn.errors[0].message.includes('consent_withdrawn'));

        const liStrictIdn = await mkIdentity();
        await seedConsent(liStrictIdn, {
            purpose: 'service_operations', consent_basis: 'legitimate_interest',
        });
        const liStrict = await captureEvents(tenantId, opsEvent(liStrictIdn));
        testThat('strict: legitimate_interest rejected even for operational events',
            !liStrict.ok && liStrict.code === 'consent_denied');

        const legalIdn = await mkIdentity();
        await seedConsent(legalIdn, {
            purpose: 'legal_compliance', consent_basis: 'legal_obligation',
        });
        const legalStrict = await captureEvents(tenantId, complianceEvent(legalIdn));
        testThat('strict: legal_obligation authorizes legal_compliance events',
            legalStrict.ok);

        const optInIdn = await mkIdentity();
        await seedConsent(optInIdn, { consent_basis: 'documented_opt_in' });
        const optIn = await captureEvents(tenantId, analyticsEvent(optInIdn));
        testThat('strict: documented_opt_in authorizes analytics', optIn.ok);

        // ---- Standard posture ----
        await setPosture('standard');

        const liStdIdn = await mkIdentity();
        await seedConsent(liStdIdn, {
            purpose: 'service_operations', consent_basis: 'legitimate_interest',
        });
        const liStdOps = await captureEvents(tenantId, opsEvent(liStdIdn));
        testThat('standard: legitimate_interest authorizes operational events', liStdOps.ok);

        const liStdAnalyticsIdn = await mkIdentity();
        await seedConsent(liStdAnalyticsIdn, { consent_basis: 'legitimate_interest' });
        const liStdAnalytics = await captureEvents(tenantId, analyticsEvent(liStdAnalyticsIdn));
        testThat('standard: legitimate_interest does NOT authorize analytics',
            !liStdAnalytics.ok && liStdAnalytics.errors[0].message.includes('basis_insufficient'));

        const contractIdn = await mkIdentity();
        await seedConsent(contractIdn, {
            purpose: 'service_operations', consent_basis: 'contract',
        });
        const contractStd = await captureEvents(tenantId, opsEvent(contractIdn));
        testThat('standard: contract authorizes service_operations events', contractStd.ok);

        const undocStdIdn = await mkIdentity();
        await seedConsent(undocStdIdn, {
            purpose: 'service_operations', consent_basis: 'undocumented',
        });
        const undocStd = await captureEvents(tenantId, opsEvent(undocStdIdn));
        testThat('standard: undocumented rejected even for operational events',
            !undocStd.ok && undocStd.code === 'consent_denied');

        // ---- Legacy posture ----
        await setPosture('legacy');

        const undocLegacyIdn = await mkIdentity();
        await seedConsent(undocLegacyIdn, {
            purpose: 'service_operations', consent_basis: 'undocumented',
        });
        const undocLegacyOps = await captureEvents(tenantId, opsEvent(undocLegacyIdn));
        testThat('legacy: undocumented authorizes operational events (limited use)',
            undocLegacyOps.ok);

        const undocLegacyAnIdn = await mkIdentity();
        await seedConsent(undocLegacyAnIdn, { consent_basis: 'undocumented' });
        const undocLegacyAnalytics = await captureEvents(tenantId, analyticsEvent(undocLegacyAnIdn));
        testThat('legacy: undocumented never authorizes analytics',
            !undocLegacyAnalytics.ok && undocLegacyAnalytics.code === 'consent_denied');

        // ---- Deny-precedence across non-implicated dimensions ----
        await setPosture('strict');

        const denyPrecIdn = await mkIdentity();
        await seedConsent(denyPrecIdn, { vendor: 'vendor_a', state: 'granted' });
        await seedConsent(denyPrecIdn, { vendor: 'vendor_b', state: 'denied' });
        const denyPrec = await captureEvents(tenantId, analyticsEvent(denyPrecIdn));
        testThat('a denial on ANY matching row blocks capture (deny-precedence)',
            !denyPrec.ok && denyPrec.code === 'consent_denied');

        // ---- Anonymous events: holding pattern, not rejection ----
        const anonEvt = makeEvent();
        const anonCapture = await captureEvents(tenantId, anonEvt);
        testThat('anonymous event captured without consent lookup', anonCapture.ok);
        const anonRow = await query(
            `SELECT consent_snapshot FROM events WHERE tenant_id = $1 AND event_id = $2`,
            [tenantId, anonEvt.event_id]);
        testThat('anonymous snapshot records the holding pattern (Decision 21 pending)',
            anonRow.rows[0].consent_snapshot.status === 'anonymous_holding',
            JSON.stringify(anonRow.rows[0].consent_snapshot));

        // ---- Reject-all: consent failures reject the whole batch ----
        const anonInBatch = makeEvent();
        const mixedConsentBatch = await captureEvents(tenantId, [
            anonInBatch,
            analyticsEvent(await mkIdentity()),   // fresh identity, no consent
        ]);
        testThat('batch with one non-consented event rejected entirely',
            !mixedConsentBatch.ok && mixedConsentBatch.code === 'consent_denied');
        testThat('consent errors carry the failing event index',
            mixedConsentBatch.errors[0].index === 1);
        const anonPersisted = await query(
            `SELECT count(*)::int AS n FROM events WHERE tenant_id = $1 AND event_id = $2`,
            [tenantId, anonInBatch.event_id]);
        test('reject-all: the anonymous sibling was not persisted', anonPersisted.rows[0].n, 0);

        // ---- Fail-closed on consent-check infrastructure failure ----
        // Break the consent lookup deterministically by renaming the table,
        // then restore it. The failing query aborts the transaction, so the
        // whole batch rolls back: fail-closed, reported honestly.
        const failClosedEvt = makeEvent({ identity_id: identityId });
        await query(`ALTER TABLE current_consent RENAME TO current_consent_broken`);
        let failClosed;
        try {
            failClosed = await captureEvents(tenantId, failClosedEvt);
        } finally {
            await query(`ALTER TABLE current_consent_broken RENAME TO current_consent`);
        }
        testThat('consent lookup failure -> consent_check_unavailable',
            !failClosed.ok && failClosed.code === 'consent_check_unavailable');
        const failClosedPersisted = await query(
            `SELECT count(*)::int AS n FROM events WHERE tenant_id = $1 AND event_id = $2`,
            [tenantId, failClosedEvt.event_id]);
        test('nothing persisted when consent could not be verified (fail-closed)',
            failClosedPersisted.rows[0].n, 0);

        // ---- Clock boundaries (Session 5, HIGH-1 / MEDIUM-1) ----
        const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

        // Expiring grant: capture allowed inside the window, denied the
        // moment it lapses - no superseding write required.
        const expIdn = await mkIdentity();
        await seedConsent(expIdn, {
            effective_from: new Date(Date.now() - 86400000).toISOString(),
            effective_until: new Date(Date.now() + 1500).toISOString(),
        });
        const insideWindow = await captureEvents(tenantId, analyticsEvent(expIdn));
        testThat('capture allowed inside the grant window', insideWindow.ok);
        await sleep(2000);
        const afterExpiry = await captureEvents(tenantId, analyticsEvent(expIdn));
        testThat('capture DENIED once the grant window lapses (HIGH-1 closed)',
            !afterExpiry.ok && afterExpiry.code === 'consent_denied');
        testThat('post-expiry rejection reads as no consent record',
            afterExpiry.errors[0].message.includes('no_consent_record'));

        // Future-dated grant: denied before AND after its window starts (the
        // documented position: live activation requires the window to have
        // started at write time; verticals schedule at the module layer).
        const futIdn = await mkIdentity();
        await seedConsent(futIdn, {
            effective_from: new Date(Date.now() + 1500).toISOString(),
        });
        const beforeStart = await captureEvents(tenantId, analyticsEvent(futIdn));
        testThat('capture denied before a future grant starts',
            !beforeStart.ok && beforeStart.code === 'consent_denied');
        await sleep(2000);
        const afterStart = await captureEvents(tenantId, analyticsEvent(futIdn));
        testThat('capture still denied after the future start (documented position: write-time activation)',
            !afterStart.ok && afterStart.code === 'consent_denied');

        // ---- Audit integration (Step 8): every capture outcome leaves a row ----
        const lastAudit = async (action) => (await query(
            `SELECT actor, outcome, outcome_reason, detail FROM audit_log
             WHERE tenant_id = $1 AND audit_action = $2
             ORDER BY occurred_at DESC, audit_id DESC LIMIT 1`, [tenantId, action])).rows[0];

        const auditOkIdn = await mkIdentity();
        await seedConsent(auditOkIdn);
        const auditOkEvt = makeEvent({ identity_id: auditOkIdn });
        await captureEvents(tenantId, [auditOkEvt, makeEvent()]);
        const allowedRow = await lastAudit('capture_allowed');
        testThat('capture_allowed row lands with actor + batch counts',
            allowedRow && allowedRow.actor === TEST_ACTOR &&
            allowedRow.outcome === 'success' &&
            allowedRow.detail.event_count === 2 && allowedRow.detail.created === 2,
            JSON.stringify(allowedRow));
        testThat('capture_allowed detail carries the event ids',
            allowedRow.detail.event_ids.includes(auditOkEvt.event_id));

        await captureEvents(tenantId, analyticsEvent(await mkIdentity())); // no consent -> denied
        const deniedRow = await lastAudit('capture_denied');
        testThat('capture_denied row lands with the enforcement reason',
            deniedRow && deniedRow.outcome === 'denied' &&
            deniedRow.outcome_reason === 'no_consent_record' &&
            deniedRow.detail.denied.length === 1,
            JSON.stringify(deniedRow));

        // The earlier fail-closed fault injection (current_consent renamed)
        // produced a capture_unavailable refusal; its audit row was written
        // best-effort AFTER the rollback, so it must exist even though the
        // events do not.
        const unavailableRow = await lastAudit('capture_unavailable');
        testThat('capture_unavailable row recorded the refusal (post-rollback, best-effort)',
            unavailableRow && unavailableRow.outcome === 'unavailable' &&
            unavailableRow.outcome_reason === 'consent_check_unavailable',
            JSON.stringify(unavailableRow));

    } finally {
        section('Teardown');
        try {
            await teardown();
            console.log(`${colors.green}✓${colors.reset} Cleaned up test tenants`);
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

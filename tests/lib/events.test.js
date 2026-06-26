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
    captureEvents,
    MAX_BATCH_SIZE,
} = require('../../src/lib/events');

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

        const badSession = validateEvent(makeEvent({ session_id: 'nope' }));
        testThat('non-UUID session_id rejected', !badSession.valid &&
            badSession.errors.some(e => e.field === 'session_id'));

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

        const notObj = validateEventsRequest('hello');
        testThat('string body rejected', !notObj.valid &&
            notObj.errors.some(e => e.code === 'invalid_type'));

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
        testThat('consent_snapshot marked not_evaluated',
            row.rows[0].consent_snapshot && row.rows[0].consent_snapshot.status === 'not_evaluated');

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

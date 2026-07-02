// ============================================================================
// ThreadOS Core - Audit Library Tests
// ============================================================================
//
// Exercises src/lib/audit.js: the typed constructors (shapes, truncation,
// subject derivation), writeAudit validation, real inserts - and the
// FAIL-CLOSED property, proven by fault injection: with the audit_log table
// renamed away, a consent recording must roll back entirely. A consent
// record that cannot be audited does not exist afterward.
//
// Usage:
//   node tests/lib/audit.test.js
// ============================================================================

require('dotenv').config();

const crypto = require('crypto');
const { query, withTransaction, shutdown } = require('../../src/lib/db');
const {
    AUDIT_ACTIONS,
    AUDIT_OUTCOMES,
    ACTOR_CORE_BACKFILL,
    ID_LIST_LIMIT,
    writeAudit,
    auditConsentRecorded,
    auditConsentRead,
    auditCaptureAllowed,
    auditCaptureDenied,
    auditCaptureUnavailable,
    auditIdentityHashed,
    auditBackfillEvaluated,
} = require('../../src/lib/audit');
const { recordConsent } = require('../../src/lib/consent');

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

async function expectThrow(name, fn, messageFragment) {
    try {
        await fn();
        testThat(name, false, 'did not throw');
    } catch (err) {
        testThat(name, !messageFragment || err.message.includes(messageFragment),
            `threw, but message was: ${err.message}`);
    }
}

// ----------------------------------------------------------------------------
// Fixtures
// ----------------------------------------------------------------------------

const TEST_TENANT_SLUG = '_test_tenant_audit_lib';
let tenantId = null;
let identityId = null;

const uuids = (n) => Array.from({ length: n }, () => crypto.randomUUID());

async function setup() {
    await query(`DELETE FROM tenants WHERE slug = $1`, [TEST_TENANT_SLUG]);
    const t = await query(
        `INSERT INTO tenants (slug, display_name, vertical_module)
         VALUES ($1, 'Audit Lib Test Tenant', 'test') RETURNING id`,
        [TEST_TENANT_SLUG]);
    tenantId = t.rows[0].id;

    const idn = await query(
        `INSERT INTO identities (tenant_id, email_hash, resolution_key, match_source)
         VALUES ($1, $2, $3, 'deterministic') RETURNING id`,
        [tenantId, crypto.randomBytes(32).toString('hex'), crypto.randomBytes(32).toString('hex')]);
    identityId = idn.rows[0].id;
}

async function teardown() {
    try {
        await query(`DELETE FROM audit_log WHERE tenant_id = $1`, [tenantId]);
        await query(`DELETE FROM tenants WHERE slug = $1`, [TEST_TENANT_SLUG]);
    } catch (err) {
        console.log(`${colors.yellow}⚠${colors.reset} Cleanup failed: ${err.message}`);
    }
    await shutdown();
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

async function runTests() {
    console.log(`${colors.bold}ThreadOS Core - Audit Library Tests${colors.reset}`);

    try {
        section('Setup');
        await setup();
        console.log(`${colors.green}✓${colors.reset} Test tenant: ${tenantId}`);

        // --------------------------------------------------------------------
        section('Typed constructors');
        // --------------------------------------------------------------------

        const recIds = uuids(3);
        const rec = auditConsentRecorded('vert-a', tenantId,
            { recordIds: recIds, created: 2, updated: 1, identityIds: [identityId, identityId] });
        test('consent_recorded action', rec.action, 'consent_recorded');
        test('consent_recorded outcome', rec.outcome, 'success');
        test('single-identity batch derives the subject', rec.subjectIdentityId, identityId);
        test('detail carries counts and ids',
            rec.detail, { record_count: 3, created: 2, updated: 1, record_ids: recIds });

        const multi = auditConsentRecorded('vert-a', tenantId,
            { recordIds: recIds, created: 3, updated: 0, identityIds: uuids(2) });
        test('multi-identity batch has no single subject', multi.subjectIdentityId, null);

        const many = auditConsentRecorded('vert-a', tenantId,
            { recordIds: uuids(ID_LIST_LIMIT + 5), created: 25, updated: 0, identityIds: [identityId] });
        test(`id lists truncate at ${ID_LIST_LIMIT}`,
            many.detail.record_ids.length, ID_LIST_LIMIT);
        test('truncation is flagged', many.detail.record_ids_truncated, true);
        test('the count carries the full truth', many.detail.record_count, ID_LIST_LIMIT + 5);

        const read = auditConsentRead('vert-a', tenantId, identityId,
            { includedHistory: true, currentTuples: 4, historyRecords: 10 });
        test('consent_read shape', read.detail,
            { included_history: true, current_tuples: 4, history_records: 10 });
        test('consent_read subject is the identity', read.subjectIdentityId, identityId);

        const denied = auditCaptureDenied('vert-a', tenantId, {
            eventCount: 3,
            denials: [
                { index: 1, identity_id: identityId, purpose: 'analytics', reason: 'no_consent_record' },
                { index: 2, identity_id: identityId, purpose: 'analytics', reason: 'basis_insufficient' },
            ],
        });
        test('capture_denied outcome', denied.outcome, 'denied');
        test('outcome_reason is the first denial reason', denied.outcomeReason, 'no_consent_record');
        test('capture_denied detail carries the breakdown', denied.detail.denied.length, 2);

        const unavailable = auditCaptureUnavailable('vert-a', tenantId, { eventCount: 5 });
        test('capture_unavailable outcome', unavailable.outcome, 'unavailable');
        test('capture_unavailable reason', unavailable.outcomeReason, 'consent_check_unavailable');

        const hashed = auditIdentityHashed('vert-a', tenantId, identityId,
            { created: true, fieldsProvided: ['email', 'name'] });
        test('identity_hashed detail names fields only',
            hashed.detail, { identity_created: true, fields_provided: ['email', 'name'] });

        const backfill = auditBackfillEvaluated(tenantId, {
            evaluated: 10, granted: 6, denied: 3, anonymousHolding: 1,
            deniedReasons: { no_consent_record: 3 }, dryRun: false,
        });
        test('backfill actor is the reserved core_backfill', backfill.actor, ACTOR_CORE_BACKFILL);
        test('backfill detail carries dispositions', backfill.detail.granted, 6);

        // --------------------------------------------------------------------
        section('writeAudit validation (throws - a malformed entry is a bug)');
        // --------------------------------------------------------------------

        const fakeClient = { query: async () => ({ rows: [] }) };
        await expectThrow('unknown action throws',
            () => writeAudit(fakeClient, { action: 'login', actor: 'a', tenantId, outcome: 'success' }),
            'unknown audit action');
        await expectThrow('unknown outcome throws',
            () => writeAudit(fakeClient, { action: 'consent_read', actor: 'a', tenantId, outcome: 'ok' }),
            'unknown audit outcome');
        await expectThrow('missing actor throws',
            () => writeAudit(fakeClient, { action: 'consent_read', tenantId, outcome: 'success' }),
            'actor');
        await expectThrow('missing tenantId throws',
            () => writeAudit(fakeClient, { action: 'consent_read', actor: 'a', outcome: 'success' }),
            'tenantId');
        await expectThrow('oversized detail throws before reaching the database',
            () => writeAudit(fakeClient, {
                action: 'consent_read', actor: 'a', tenantId, outcome: 'success',
                detail: { blob: 'x'.repeat(5000) },
            }), 'detail exceeds');
        await expectThrow('missing client throws',
            () => writeAudit(null, { action: 'consent_read', actor: 'a', tenantId, outcome: 'success' }),
            'transaction client');

        test('vocabularies are frozen',
            [Object.isFrozen(AUDIT_ACTIONS), Object.isFrozen(AUDIT_OUTCOMES)], [true, true]);

        // --------------------------------------------------------------------
        section('writeAudit inserts (in a real transaction)');
        // --------------------------------------------------------------------

        await withTransaction(async (client) => {
            await writeAudit(client, auditConsentRead('vert-b', tenantId, identityId,
                { includedHistory: false, currentTuples: 0 }));
        });
        const inserted = await query(
            `SELECT actor, audit_action, outcome, subject_identity_id, detail
             FROM audit_log WHERE tenant_id = $1 AND actor = 'vert-b'`, [tenantId]);
        test('row landed', inserted.rows.length, 1);
        test('row content', inserted.rows[0].audit_action, 'consent_read');
        test('row subject', inserted.rows[0].subject_identity_id, identityId);

        // --------------------------------------------------------------------
        section('FAIL-CLOSED: an action that cannot be audited does not happen');
        // --------------------------------------------------------------------

        // Fault-inject the audit insert by renaming the table, then attempt a
        // real consent recording. The audit failure must roll back the whole
        // transaction: afterward the consent record must NOT exist.
        const record = {
            identity_id: identityId,
            purpose: 'analytics', vendor: 'fail_closed_vendor', channel: 'email',
            data_category: 'behavioral', jurisdiction: 'US',
            state: 'granted', consent_basis: 'active_consent', captured_via: 'web_form',
            capture_context: 'Fail-closed audit test',
            reason: 'Fail-closed audit test',
            effective_from: new Date(Date.now() - 86400000).toISOString(),
        };

        await query(`ALTER TABLE audit_log RENAME TO audit_log_broken`);
        let failClosedError = null;
        try {
            await recordConsent(tenantId, record, '_test_audit_lib');
        } catch (err) {
            failClosedError = err;
        } finally {
            await query(`ALTER TABLE audit_log_broken RENAME TO audit_log`);
        }

        testThat('recording with a broken audit path throws', failClosedError !== null);
        const orphan = await query(
            `SELECT 1 FROM consent_records WHERE tenant_id = $1 AND vendor = 'fail_closed_vendor'`,
            [tenantId]);
        test('the consent record does NOT exist (transaction rolled back)',
            orphan.rows.length, 0);
        const orphanProjection = await query(
            `SELECT 1 FROM current_consent WHERE tenant_id = $1 AND vendor = 'fail_closed_vendor'`,
            [tenantId]);
        test('the projection was not touched either', orphanProjection.rows.length, 0);

        // Sanity: with the table restored, the same recording succeeds and is
        // audited.
        const recovered = await recordConsent(tenantId, record, '_test_audit_lib');
        testThat('same recording succeeds once auditable', recovered.ok);
        const auditRow = await query(
            `SELECT outcome FROM audit_log
             WHERE tenant_id = $1 AND actor = '_test_audit_lib' AND audit_action = 'consent_recorded'`,
            [tenantId]);
        test('and its audit row exists', auditRow.rows.length, 1);

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

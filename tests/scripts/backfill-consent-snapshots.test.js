// ============================================================================
// ThreadOS Core - Consent Snapshot Backfill Tests
// ============================================================================
//
// Exercises scripts/backfill-consent-snapshots.js as the real artifact (via
// child_process) against seeded pre-enforcement events. Proves:
//
//   - Point-in-time evaluation: an event is judged by the consent in effect
//     AT event_timestamp (bitemporal reconstruction), not the current
//     projection - in both directions.
//   - Disposition writes: granted snapshots cite the authorizing record;
//     denied events get retention_status = 'expired'; anonymous events get
//     the holding snapshot with retention untouched.
//   - Dry-run writes nothing.
//   - Idempotency: a second run finds nothing to do.
//
// Usage:
//   node tests/scripts/backfill-consent-snapshots.test.js
// ============================================================================

require('dotenv').config();

const crypto = require('crypto');
const path = require('path');
const { execFileSync } = require('child_process');
const { query, shutdown } = require('../../src/lib/db');
const { recordConsent: recordConsentRaw } = require('../../src/lib/consent');

// Step 8: consent writes carry an actor for the audit trail.
const recordConsent = (t, b, actor = '_test_backfill') => recordConsentRaw(t, b, actor);

const SCRIPT = path.join(__dirname, '../../scripts/backfill-consent-snapshots.js');
const TEST_TENANT_SLUG = '_test_tenant_backfill';
let tenantId = null;
let identityId = null;

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

function daysAgo(n) {
    return new Date(Date.now() - n * 24 * 60 * 60 * 1000).toISOString();
}

const NOT_EVALUATED = { status: 'not_evaluated', reason: 'consent_enforcement_pending_step_7' };

// Insert an event the way Step 6 left them: placeholder snapshot, standard
// retention.
async function insertLegacyEvent(overrides = {}) {
    const evt = {
        event_id: crypto.randomUUID(),
        identity_id: identityId,
        session_id: crypto.randomUUID(),
        event_name: 'page_viewed',
        event_category: 'engagement',
        event_timestamp: daysAgo(10),
        ...overrides,
    };
    await query(
        `INSERT INTO events (
            tenant_id, event_id, identity_id, session_id, source_type,
            event_name, event_category, properties, consent_snapshot,
            event_timestamp, validation_status
         ) VALUES ($1, $2, $3, $4, 'web', $5, $6, '{}', $7, $8, 'valid')`,
        [tenantId, evt.event_id, evt.identity_id, evt.session_id,
            evt.event_name, evt.event_category, NOT_EVALUATED, evt.event_timestamp]
    );
    return evt;
}

async function eventState(eventId) {
    const res = await query(
        `SELECT consent_snapshot, retention_status FROM events
         WHERE tenant_id = $1 AND event_id = $2`,
        [tenantId, eventId]
    );
    return res.rows[0];
}

async function seedConsent(overrides = {}) {
    const result = await recordConsent(tenantId, {
        identity_id: identityId,
        purpose: 'analytics',
        vendor: 'acme_dms',
        channel: 'in_app',
        data_category: 'behavioral',
        jurisdiction: 'US',
        state: 'granted',
        consent_basis: 'active_consent',
        captured_via: 'web_form',
        capture_context: 'Backfill test consent fixture',
        reason: 'Backfill test consent fixture',
        effective_from: daysAgo(30),
        effective_until: null,
        ...overrides,
    });
    if (!result.ok) {
        throw new Error(`seedConsent failed: ${JSON.stringify(result.errors)}`);
    }
}

function runScript(extraArgs = []) {
    return execFileSync('node', [SCRIPT, ...extraArgs], {
        encoding: 'utf8',
        env: process.env,
        cwd: path.join(__dirname, '../..'),
    });
}

async function setup() {
    await query(`DELETE FROM tenants WHERE slug = $1`, [TEST_TENANT_SLUG]);

    const t = await query(
        `INSERT INTO tenants (slug, display_name, vertical_module, compliance_posture)
         VALUES ($1, 'Backfill Test Tenant', 'test', 'strict') RETURNING id`,
        [TEST_TENANT_SLUG]
    );
    tenantId = t.rows[0].id;

    const idn = await query(
        `INSERT INTO identities (tenant_id, email_hash, resolution_key, match_source)
         VALUES ($1, $2, $3, 'deterministic') RETURNING id`,
        [tenantId, '9'.repeat(64), '0'.repeat(64)]
    );
    identityId = idn.rows[0].id;

    await query(
        `INSERT INTO event_type_registry (tenant_id, event_name, event_category)
         VALUES ($1, 'page_viewed', 'engagement')
         ON CONFLICT (tenant_id, event_name) DO NOTHING`,
        [tenantId]
    );
}

async function teardown() {
    try {
        // audit_log has no FKs (by design) - clean explicitly.
        if (tenantId) await query(`DELETE FROM audit_log WHERE tenant_id = $1`, [tenantId]);
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
    console.log(`${colors.bold}ThreadOS Core - Consent Snapshot Backfill Tests${colors.reset}`);

    try {
        section('Setup');
        await setup();
        console.log(`${colors.green}✓${colors.reset} Test tenant: ${tenantId}`);

        // Consent timeline for the shared identity (all same dimension tuple):
        //   daysAgo(30): granted, active_consent
        //   daysAgo(5):  withdrawn (supersedes)
        // Current projection therefore says WITHDRAWN.
        await seedConsent({ effective_from: daysAgo(30) });
        await seedConsent({ state: 'withdrawn', effective_from: daysAgo(5) });

        // Identity #2: consent granted only recently (daysAgo(2)) - nothing
        // was in effect ten days ago. Current projection says GRANTED.
        const lateIdn = await query(
            `INSERT INTO identities (tenant_id, email_hash, resolution_key, match_source)
             VALUES ($1, $2, $3, 'deterministic') RETURNING id`,
            [tenantId, 'a1'.repeat(32), 'b2'.repeat(32)]
        );
        const lateIdentityId = lateIdn.rows[0].id;
        await recordConsent(tenantId, {
            identity_id: lateIdentityId,
            purpose: 'analytics', vendor: 'acme_dms', channel: 'in_app',
            data_category: 'behavioral', jurisdiction: 'US',
            state: 'granted', consent_basis: 'active_consent', captured_via: 'web_form',
            capture_context: 'Backfill test consent fixture',
            reason: 'Backfill test consent fixture',
            effective_from: daysAgo(2), effective_until: null,
        });

        // Identity #3: only an undocumented-basis grant, in effect at event
        // time; tenant posture is strict.
        const undocIdn = await query(
            `INSERT INTO identities (tenant_id, email_hash, resolution_key, match_source)
             VALUES ($1, $2, $3, 'deterministic') RETURNING id`,
            [tenantId, 'c3'.repeat(32), 'd4'.repeat(32)]
        );
        const undocIdentityId = undocIdn.rows[0].id;
        await recordConsent(tenantId, {
            identity_id: undocIdentityId,
            purpose: 'analytics', vendor: 'acme_dms', channel: 'in_app',
            data_category: 'behavioral', jurisdiction: 'US',
            state: 'granted', consent_basis: 'undocumented', captured_via: 'imported',
            capture_context: 'Backfill test consent fixture',
            reason: 'Backfill test consent fixture',
            effective_from: daysAgo(30), effective_until: null,
        });

        // Pre-enforcement events (ts = daysAgo(10) unless stated):
        const grantedThenWithdrawn = await insertLegacyEvent();            // granted at ts, withdrawn NOW
        const noConsentAtTs = await insertLegacyEvent({ identity_id: lateIdentityId }); // granted NOW, nothing at ts
        const withdrawnAtTs = await insertLegacyEvent({ event_timestamp: daysAgo(3) }); // withdrawn at ts
        const undocAtTs = await insertLegacyEvent({ identity_id: undocIdentityId });    // basis fails strict
        const anonymous = await insertLegacyEvent({ identity_id: null });               // no identity

        // --------------------------------------------------------------------
        section('Dry run writes nothing');
        // --------------------------------------------------------------------

        const dryOut = runScript(['--dry-run']);
        testThat('dry run reports evaluations', dryOut.includes('dry run complete'));
        const afterDry = await eventState(grantedThenWithdrawn.event_id);
        test('dry run left the placeholder in place',
            afterDry.consent_snapshot.status, 'not_evaluated');
        const dryAudit = await query(
            `SELECT count(*)::int AS n FROM audit_log
             WHERE tenant_id = $1 AND audit_action = 'backfill_evaluated'`, [tenantId]);
        test('dry run wrote no audit row (writes NOTHING per its contract)',
            dryAudit.rows[0].n, 0);

        // --------------------------------------------------------------------
        section('Backfill: point-in-time evaluation');
        // --------------------------------------------------------------------

        runScript();

        const s1 = await eventState(grantedThenWithdrawn.event_id);
        test('consent in effect AT event time -> granted, despite current withdrawal',
            s1.consent_snapshot.status, 'granted');
        testThat('granted snapshot cites basis and authorizing record',
            s1.consent_snapshot.basis === 'active_consent' &&
            !!s1.consent_snapshot.source_record_id &&
            s1.consent_snapshot.backfilled === true,
            JSON.stringify(s1.consent_snapshot));
        test('granted event keeps standard retention', s1.retention_status, 'standard');

        const s2 = await eventState(noConsentAtTs.event_id);
        test('no consent at event time -> denied, despite current grant',
            s2.consent_snapshot.status, 'denied');
        test('denial reason recorded', s2.consent_snapshot.reason, 'no_consent_record');
        test('denied event expired out of retention', s2.retention_status, 'expired');

        const s3 = await eventState(withdrawnAtTs.event_id);
        test('withdrawal in effect at event time -> denied',
            s3.consent_snapshot.status, 'denied');
        test('withdrawal reason recorded', s3.consent_snapshot.reason, 'consent_withdrawn');

        const s4 = await eventState(undocAtTs.event_id);
        test('undocumented basis under strict posture -> denied',
            s4.consent_snapshot.status, 'denied');
        test('basis reason recorded', s4.consent_snapshot.reason, 'basis_insufficient');

        const s5 = await eventState(anonymous.event_id);
        test('anonymous event -> anonymous_holding',
            s5.consent_snapshot.status, 'anonymous_holding');
        test('anonymous event retention untouched', s5.retention_status, 'standard');

        // --------------------------------------------------------------------
        section('Idempotency');
        // --------------------------------------------------------------------

        const secondRun = runScript();
        testThat('second run finds nothing to backfill',
            secondRun.includes('0 event(s) backfilled'), secondRun);
        const s1Again = await eventState(grantedThenWithdrawn.event_id);
        test('second run left evaluated snapshots untouched',
            s1Again.consent_snapshot.evaluated_at, s1.consent_snapshot.evaluated_at);

        // --------------------------------------------------------------------
        section('Audit integration (Step 8): the run is on the record');
        // --------------------------------------------------------------------

        const runAudit = await query(
            `SELECT actor, outcome, detail FROM audit_log
             WHERE tenant_id = $1 AND audit_action = 'backfill_evaluated'`, [tenantId]);
        test('exactly one backfill_evaluated row for the tenant (real run only)',
            runAudit.rows.length, 1);
        test('actor is the reserved core_backfill', runAudit.rows[0].actor, 'core_backfill');
        testThat('detail carries the tenant\'s disposition counts',
            runAudit.rows[0].detail.evaluated === 5 &&
            runAudit.rows[0].detail.granted === 1 &&
            runAudit.rows[0].detail.denied === 3 &&
            runAudit.rows[0].detail.anonymous_holding === 1 &&
            runAudit.rows[0].detail.denied_reasons.no_consent_record === 1,
            JSON.stringify(runAudit.rows[0].detail));

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

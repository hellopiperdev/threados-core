// ============================================================================
// ThreadOS Core - Consent Snapshot Backfill (Step 7 Session 4)
// ============================================================================
//
// Re-evaluates the events captured before write-time consent enforcement
// existed (Step 6) - the rows marked consent_snapshot->>'status' =
// 'not_evaluated' - and replaces the placeholder with a real evaluation.
//
// Evaluation is POINT-IN-TIME, not against the current projection: for each
// event we reconstruct the consent that was in effect AT event_timestamp
// from the bitemporal consent_records history (effective_from <= ts <
// effective_until, latest effective_from per dimension tuple), then apply
// the same rule map (src/lib/enforcement.js) under the tenant's compliance
// posture with the event type's implicated purpose. This answers the
// defensible question - "was there consent when it happened?" - not "would
// we accept it now?".
//
// Dispositions (per the settled Session 4 ruling - mark, don't delete):
//   granted            snapshot records the evaluation + authorizing record
//   denied             snapshot records the reason; retention_status set to
//                      'expired' so the event drops out of future read paths.
//                      Purging is the retention/erasure workflow's job.
//   anonymous_holding  no identity_id: nothing to evaluate against; pending
//                      the Decision 21 holding-pattern implementation.
//
// Idempotent by construction: only 'not_evaluated' rows are touched, and
// every touched row leaves that state. Safe to re-run; a second run finds
// nothing.
//
// Usage:
//   node scripts/backfill-consent-snapshots.js [--dry-run] [--batch-size=N]
//
//   --dry-run       evaluate and report, write nothing
//   --batch-size=N  events per transaction (default 200)
//
// Bible references:
//   Decision 13: Multi-dimensional consent (purpose per event type)
//   Decision 14: Tenant compliance postures
//   Decision 15: Write-time consent enforcement (this settles its debt to
//                the pre-enforcement Step 6 events)
// ============================================================================

require('dotenv').config();

const { query, withTransaction, shutdown } = require('../src/lib/db');
const { evaluateCapture } = require('../src/lib/enforcement');
const { writeAudit, auditBackfillEvaluated } = require('../src/lib/audit');

const colors = {
    reset: '\x1b[0m',
    bold: '\x1b[1m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    red: '\x1b[31m',
    blue: '\x1b[34m',
    gray: '\x1b[90m',
};

const log = {
    section: (msg) => console.log(`\n${colors.bold}${colors.blue}━━ ${msg} ━━${colors.reset}`),
    step: (msg) => console.log(`${colors.gray}→${colors.reset} ${msg}`),
    success: (msg) => console.log(`${colors.green}✓${colors.reset} ${msg}`),
    warn: (msg) => console.log(`${colors.yellow}⚠${colors.reset} ${msg}`),
    error: (msg) => console.log(`${colors.red}✗${colors.reset} ${msg}`),
    info: (msg) => console.log(`  ${colors.gray}${msg}${colors.reset}`),
};

// ----------------------------------------------------------------------------
// Arguments
// ----------------------------------------------------------------------------

const args = process.argv.slice(2);
const DRY_RUN = args.includes('--dry-run');
const batchArg = args.find(a => a.startsWith('--batch-size='));
const BATCH_SIZE = batchArg ? parseInt(batchArg.split('=')[1], 10) : 200;

if (!Number.isInteger(BATCH_SIZE) || BATCH_SIZE < 1 || BATCH_SIZE > 5000) {
    log.error(`--batch-size must be an integer between 1 and 5000 (got "${batchArg}")`);
    process.exit(1);
}

const ANONYMOUS_HOLDING_REASON = 'pre_identification_holding_pending_decision_21';

// ----------------------------------------------------------------------------
// Point-in-time consent reconstruction
// ----------------------------------------------------------------------------
//
// The rows in effect at `atTimestamp` for (tenant, identity, purpose,
// behavioral): one row per (vendor, channel, jurisdiction) tuple, the one
// with the latest effective_from (recorded_at DESC as system-time tiebreak).
// DISTINCT ON does the per-tuple supersession in one query.
// ----------------------------------------------------------------------------

async function consentInEffectAt(client, tenantId, identityId, purpose, atTimestamp) {
    const result = await client.query(
        `SELECT DISTINCT ON (vendor, channel, jurisdiction)
                record_id, state, consent_basis, effective_from
         FROM consent_records
         WHERE tenant_id = $1 AND identity_id = $2
           AND purpose = $3 AND data_category = 'behavioral'
           AND effective_from <= $4
           AND (effective_until IS NULL OR effective_until > $4)
         ORDER BY vendor, channel, jurisdiction, effective_from DESC, recorded_at DESC`,
        [tenantId, identityId, purpose, atTimestamp]
    );
    return result.rows;
}

// ----------------------------------------------------------------------------
// Per-event evaluation
// ----------------------------------------------------------------------------

async function evaluateEvent(client, evt, postureByTenant, purposeCache) {
    const evaluatedAt = new Date().toISOString();

    if (!evt.identity_id) {
        return {
            disposition: 'anonymous_holding',
            snapshot: {
                status: 'anonymous_holding',
                reason: ANONYMOUS_HOLDING_REASON,
                evaluated_at: evaluatedAt,
                backfilled: true,
            },
        };
    }

    const posture = postureByTenant.get(evt.tenant_id);

    // The event type's implicated purpose. A registry row must have existed
    // at capture time; if it has since been deleted or deactivated we fall
    // back to 'analytics' - the most consent-gated purpose - so the orphan
    // fails CLOSED rather than open.
    const purposeKey = `${evt.tenant_id}|${evt.event_name}`;
    let purpose = purposeCache.get(purposeKey);
    if (purpose === undefined) {
        const reg = await client.query(
            `SELECT implicated_purpose FROM event_type_registry
             WHERE tenant_id = $1 AND event_name = $2`,
            [evt.tenant_id, evt.event_name]
        );
        purpose = reg.rows.length > 0 ? reg.rows[0].implicated_purpose : 'analytics';
        purposeCache.set(purposeKey, purpose);
    }

    const rows = await consentInEffectAt(
        client, evt.tenant_id, evt.identity_id, purpose, evt.event_timestamp);
    const decision = evaluateCapture(rows, posture, purpose);

    if (decision.allowed) {
        return {
            disposition: 'granted',
            snapshot: {
                status: 'granted',
                posture,
                purpose,
                basis: decision.basis,
                source_record_id: decision.record_id,
                evaluated_at: evaluatedAt,
                evaluated_as_of: evt.event_timestamp,
                backfilled: true,
            },
        };
    }

    return {
        disposition: 'denied',
        reason: decision.reason,
        snapshot: {
            status: 'denied',
            posture,
            purpose,
            reason: decision.reason,
            evaluated_at: evaluatedAt,
            evaluated_as_of: evt.event_timestamp,
            backfilled: true,
        },
    };
}

// ----------------------------------------------------------------------------
// Main
// ----------------------------------------------------------------------------

async function run() {
    console.log(`${colors.bold}ThreadOS Core - Consent Snapshot Backfill${colors.reset}`);
    if (DRY_RUN) log.warn('DRY RUN: evaluating only, writing nothing');

    const pending = await query(
        `SELECT count(*)::int AS n FROM events
         WHERE consent_snapshot->>'status' = 'not_evaluated'`
    );
    log.step(`${pending.rows[0].n} event(s) awaiting evaluation`);

    // Tenant postures, loaded once.
    const tenants = await query(`SELECT id, compliance_posture FROM tenants`);
    const postureByTenant = new Map(tenants.rows.map(t => [t.id, t.compliance_posture]));

    const counts = { granted: 0, denied: 0, anonymous_holding: 0 };
    const deniedReasons = {};
    // Per-tenant tallies for the backfill_evaluated audit rows: audit rows
    // are tenant-scoped (tenant_id NOT NULL), so a run touching multiple
    // tenants writes one row per tenant, each with that tenant's counts.
    const perTenant = new Map();
    const purposeCache = new Map();
    let processed = 0;

    // Batches keyed after the last-seen id keep each transaction bounded and
    // make the loop restartable. In dry-run mode rows stay 'not_evaluated',
    // so we page by id ourselves either way.
    let lastId = '00000000-0000-0000-0000-000000000000';

    for (;;) {
        const batch = await query(
            `SELECT id, tenant_id, identity_id, event_name, event_timestamp
             FROM events
             WHERE consent_snapshot->>'status' = 'not_evaluated' AND id > $1
             ORDER BY id
             LIMIT $2`,
            [lastId, BATCH_SIZE]
        );
        if (batch.rows.length === 0) break;
        lastId = batch.rows[batch.rows.length - 1].id;

        await withTransaction(async (client) => {
            for (const evt of batch.rows) {
                const result = await evaluateEvent(client, evt, postureByTenant, purposeCache);

                counts[result.disposition]++;
                if (result.disposition === 'denied') {
                    deniedReasons[result.reason] = (deniedReasons[result.reason] || 0) + 1;
                }

                if (!perTenant.has(evt.tenant_id)) {
                    perTenant.set(evt.tenant_id, {
                        evaluated: 0, granted: 0, denied: 0,
                        anonymous_holding: 0, deniedReasons: {},
                    });
                }
                const t = perTenant.get(evt.tenant_id);
                t.evaluated++;
                t[result.disposition]++;
                if (result.disposition === 'denied') {
                    t.deniedReasons[result.reason] = (t.deniedReasons[result.reason] || 0) + 1;
                }

                if (!DRY_RUN) {
                    if (result.disposition === 'denied') {
                        await client.query(
                            `UPDATE events
                             SET consent_snapshot = $1, retention_status = 'expired'
                             WHERE id = $2`,
                            [result.snapshot, evt.id]
                        );
                    } else {
                        await client.query(
                            `UPDATE events SET consent_snapshot = $1 WHERE id = $2`,
                            [result.snapshot, evt.id]
                        );
                    }
                }
                processed++;
            }
        });

        log.step(`processed ${processed}/${pending.rows[0].n}`);
    }

    log.section('Dispositions');
    log.success(`granted:           ${counts.granted}`);
    log.success(`denied (expired):  ${counts.denied}`);
    for (const [reason, n] of Object.entries(deniedReasons)) {
        log.info(`denied because ${reason}: ${n}`);
    }
    log.success(`anonymous_holding: ${counts.anonymous_holding}`);

    // Audit the run (Step 8): one backfill_evaluated row per tenant touched,
    // actor core_backfill. A dry run writes NOTHING - including audit rows -
    // per its contract; only runs that changed state are audited. An audit
    // failure here exits non-zero: the evaluations are committed (per-batch
    // transactions), so the operator must see that the run went unaudited.
    if (!DRY_RUN && perTenant.size > 0) {
        log.section('Audit');
        await withTransaction(async (client) => {
            for (const [tenantId, t] of perTenant) {
                await writeAudit(client, auditBackfillEvaluated(tenantId, {
                    evaluated: t.evaluated,
                    granted: t.granted,
                    denied: t.denied,
                    anonymousHolding: t.anonymous_holding,
                    deniedReasons: t.deniedReasons,
                    dryRun: false,
                }));
            }
        });
        log.success(`${perTenant.size} backfill_evaluated audit row(s) written`);
    }

    log.section('Done');
    if (DRY_RUN) {
        log.warn(`dry run complete: ${processed} event(s) evaluated, 0 written`);
    } else {
        log.success(`${processed} event(s) backfilled`);
    }

    await shutdown();
}

run().catch(async (err) => {
    log.error('Backfill failed');
    console.error(err);
    try { await shutdown(); } catch (e) { /* already closing */ }
    process.exit(1);
});

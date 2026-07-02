// ============================================================================
// ThreadOS Core - Audit Logging
// ============================================================================
//
// Core's diary of its own compliance-relevant actions, written for a hostile
// reader (a regulator, a lawyer, a future incident review): who acted, on
// whose behalf, on what subject, doing what, with what outcome, when. One
// append-only row per action. Not operator logs; not a mirror of the events
// table.
//
// FAIL-CLOSED (settled Step 8 design): writeAudit takes the caller's
// TRANSACTION CLIENT and throws on failure, which rolls the caller's whole
// transaction back. An action Core cannot audit is an action that does not
// happen. The one deliberate exception is capture_unavailable (see
// src/lib/events.js): it records a REFUSAL after the capture transaction has
// already rolled back, so it is written best-effort in its own transaction -
// when consent infrastructure is down, demanding a durable audit row before
// answering 503 would turn "cannot verify consent" into "cannot respond".
//
// Synchronous, same-database writes are the settled MVP posture. Bible
// Decision 16's architecture - separate audit instance, separate
// credentials, async Pub/Sub pipeline - is the production-hardening target
// (Step 10+, tracked in ClickUp); the append-only, survives-erasure intent
// of that decision applies now.
//
// DETAIL SHAPES (authoritative; the constructors below are the only
// sanctioned way to assemble entries). Every shape is bounded: id lists are
// truncated to ID_LIST_LIMIT entries with a *_truncated flag, keeping every
// row under the schema's 4096-char detail bound.
//
//   consent_recorded    { record_count, created, updated, record_ids,
//                         record_ids_truncated? }
//   consent_read        { included_history, current_tuples, history_records? }
//   capture_allowed     { event_count, created, duplicates, event_ids,
//                         event_ids_truncated? }
//   capture_denied      { event_count, denied: [{index, purpose, reason}],
//                         denied_truncated? }
//                        (outcome_reason carries the first denial's reason)
//   capture_unavailable { event_count }
//   identity_hashed     { identity_created, fields_provided }
//   backfill_evaluated  { evaluated, granted, denied, anonymous_holding,
//                         denied_reasons, dry_run }
//
// Bible references:
//   Decision 16: Audit logging - append-only compliance record; rows carry
//                no foreign keys so they survive erasure cascades.
//   Decision 4:  Tenant scoping - every row names the tenant it acted for
//                (from the verified JWT sub, never a request body).
//   Decision 7:  Opinionated gatekeeper - entries are validated against the
//                action/outcome vocabularies before insert; a malformed
//                audit entry is a Core bug and throws.
// ============================================================================

const AUDIT_ACTIONS = Object.freeze([
    'consent_recorded', 'consent_read',
    'capture_allowed', 'capture_denied', 'capture_unavailable',
    'backfill_evaluated', 'identity_hashed',
]);

const AUDIT_OUTCOMES = Object.freeze(['success', 'denied', 'unavailable']);

// Reserved actor for the backfill script (everything else is a verified
// vertical slug from the JWT iss claim).
const ACTOR_CORE_BACKFILL = 'core_backfill';

// Id lists inside detail are truncated to this many entries. 20 UUIDs plus
// counts sits far below the 4096-char bound; the counts carry the full
// truth, the ids are a convenience sample for review.
const ID_LIST_LIMIT = 20;

const MAX_DETAIL_CHARS = 4096;

// ----------------------------------------------------------------------------
// writeAudit
// ----------------------------------------------------------------------------
//
// Inserts one audit row using the CALLER'S transaction client (or any object
// with a pg-compatible .query, e.g. the db module itself for the paths that
// legitimately run outside a transaction - see the header). Validates the
// entry against the vocabularies and the detail bound, and THROWS on any
// problem: a failed audit write rolls back the caller's transaction, which
// is the point.
//
// entry: { action, actor, tenantId, subjectIdentityId?, outcome,
//          outcomeReason?, detail? }
// ----------------------------------------------------------------------------

async function writeAudit(client, entry) {
    if (!client || typeof client.query !== 'function') {
        throw new Error('writeAudit requires a transaction client (or query-capable handle)');
    }
    if (!entry || typeof entry !== 'object') {
        throw new Error('writeAudit requires an entry object');
    }
    if (!AUDIT_ACTIONS.includes(entry.action)) {
        throw new Error(`writeAudit: unknown audit action "${entry.action}"`);
    }
    if (!AUDIT_OUTCOMES.includes(entry.outcome)) {
        throw new Error(`writeAudit: unknown audit outcome "${entry.outcome}"`);
    }
    if (!entry.actor || typeof entry.actor !== 'string' || entry.actor.length > 100) {
        throw new Error('writeAudit: actor must be a non-empty string of 100 chars or fewer');
    }
    if (!entry.tenantId) {
        throw new Error('writeAudit: tenantId is required');
    }

    const detail = entry.detail || {};
    const serialized = JSON.stringify(detail);
    if (serialized.length > MAX_DETAIL_CHARS) {
        // The constructors bound every shape below this; hitting it means a
        // constructor was bypassed or is wrong. Throw - do not truncate a
        // compliance record silently.
        throw new Error(`writeAudit: detail exceeds ${MAX_DETAIL_CHARS} chars (${serialized.length})`);
    }

    await client.query(
        `INSERT INTO audit_log (
            audit_action, actor, tenant_id, subject_identity_id,
            outcome, outcome_reason, detail
         ) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [
            entry.action,
            entry.actor,
            entry.tenantId,
            entry.subjectIdentityId || null,
            entry.outcome,
            entry.outcomeReason || null,
            detail,
        ]
    );
}

// ----------------------------------------------------------------------------
// Typed constructors - one per action, so call sites cannot misassemble
// entries and each detail shape has exactly one authoritative builder.
// ----------------------------------------------------------------------------

function truncateIds(ids) {
    if (!Array.isArray(ids)) return { list: [], truncated: false };
    if (ids.length <= ID_LIST_LIMIT) return { list: ids, truncated: false };
    return { list: ids.slice(0, ID_LIST_LIMIT), truncated: true };
}

// One row per POST /api/v1/consent call (the call is the action, not the
// individual record). subjectIdentityId is set when the batch concerns a
// single identity; a multi-identity batch has no single subject.
function auditConsentRecorded(actor, tenantId, { recordIds, created, updated, identityIds }) {
    const { list, truncated } = truncateIds(recordIds);
    const subjects = [...new Set(identityIds || [])];
    const detail = {
        record_count: (recordIds || []).length,
        created,
        updated,
        record_ids: list,
    };
    if (truncated) detail.record_ids_truncated = true;
    return {
        action: 'consent_recorded',
        actor,
        tenantId,
        subjectIdentityId: subjects.length === 1 ? subjects[0] : null,
        outcome: 'success',
        detail,
    };
}

// One row per GET /api/v1/consent/:identity_id that disclosed data
// (Step 8 decision 8.5: reads of consent state are audited).
function auditConsentRead(actor, tenantId, identityId, { includedHistory, currentTuples, historyRecords }) {
    const detail = {
        included_history: !!includedHistory,
        current_tuples: currentTuples,
    };
    if (includedHistory) detail.history_records = historyRecords;
    return {
        action: 'consent_read',
        actor,
        tenantId,
        subjectIdentityId: identityId,
        outcome: 'success',
        detail,
    };
}

// One row per accepted capture batch.
function auditCaptureAllowed(actor, tenantId, { eventIds, created, duplicates, identityIds }) {
    const { list, truncated } = truncateIds(eventIds);
    const subjects = [...new Set((identityIds || []).filter(Boolean))];
    const detail = {
        event_count: (eventIds || []).length,
        created,
        duplicates,
        event_ids: list,
    };
    if (truncated) detail.event_ids_truncated = true;
    return {
        action: 'capture_allowed',
        actor,
        tenantId,
        subjectIdentityId: subjects.length === 1 ? subjects[0] : null,
        outcome: 'success',
        detail,
    };
}

// One row per consent-rejected capture batch. outcome_reason carries the
// first denial's machine reason (the enforcement rule cell); detail carries
// a bounded per-event breakdown.
function auditCaptureDenied(actor, tenantId, { eventCount, denials }) {
    const bounded = (denials || []).slice(0, ID_LIST_LIMIT);
    const detail = {
        event_count: eventCount,
        denied: bounded,
    };
    if ((denials || []).length > ID_LIST_LIMIT) detail.denied_truncated = true;
    const subjects = [...new Set(bounded.map(d => d.identity_id).filter(Boolean))];
    return {
        action: 'capture_denied',
        actor,
        tenantId,
        subjectIdentityId: subjects.length === 1 ? subjects[0] : null,
        outcome: 'denied',
        outcomeReason: bounded.length > 0 ? bounded[0].reason : 'consent_denied',
        detail,
    };
}

// One row per capture batch refused because consent could not be VERIFIED.
// Written best-effort outside the (already rolled back) capture transaction.
function auditCaptureUnavailable(actor, tenantId, { eventCount }) {
    return {
        action: 'capture_unavailable',
        actor,
        tenantId,
        outcome: 'unavailable',
        outcomeReason: 'consent_check_unavailable',
        detail: { event_count: eventCount },
    };
}

// One row per identity hash operation that processed PII.
function auditIdentityHashed(actor, tenantId, identityId, { created, fieldsProvided }) {
    return {
        action: 'identity_hashed',
        actor,
        tenantId,
        subjectIdentityId: identityId,
        outcome: 'success',
        detail: {
            identity_created: !!created,
            fields_provided: fieldsProvided,
        },
    };
}

// One row per backfill run (actor is the reserved core_backfill).
function auditBackfillEvaluated(tenantId, { evaluated, granted, denied, anonymousHolding, deniedReasons, dryRun }) {
    return {
        action: 'backfill_evaluated',
        actor: ACTOR_CORE_BACKFILL,
        tenantId,
        outcome: 'success',
        detail: {
            evaluated,
            granted,
            denied,
            anonymous_holding: anonymousHolding,
            denied_reasons: deniedReasons || {},
            dry_run: !!dryRun,
        },
    };
}

// ----------------------------------------------------------------------------
// Exports
// ----------------------------------------------------------------------------

module.exports = {
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
};

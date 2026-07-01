// ============================================================================
// ThreadOS Core - Consent Enforcement Rules
// ============================================================================
//
// The consent law of Core: given a tenant's compliance posture, a consent
// record's basis, and the purpose being exercised, may the operation
// proceed? This module owns the FINAL enforcement rule map (settled in the
// Step 7 Session 4 design ruling) and the evaluation functions that apply it.
//
// Event capture (src/lib/events.js) is the first enforcement touchpoint;
// future touchpoints (marketing activation, loyalty, audit review) consult
// the same map. The map is a STATIC structure in Core code by explicit
// ruling under Decision 14: enforcement rules are not per-tenant
// configurable. Tenants choose a posture; they do not edit the law.
//
// Bible references:
//   Decision 13: Multi-dimensional consent model - purpose is the dimension
//                enforcement pivots on at capture time.
//   Decision 14: Tenant-level compliance postures (strict/standard/legacy) -
//                the posture axis of the rule map.
//   Decision 15: Write-time consent enforcement - events without valid
//                consent for their purpose are rejected before storage.
//   Decision 22: Customer-over-client resolution - ambiguity fails closed.
//
// THE RULE MAP (final - do not re-derive or adjust):
//
//   Invariants under every posture:
//     - No consent record for the relevant dimension tuple -> rejected
//     - state in {denied, withdrawn} -> rejected
//     - state = granted -> basis x posture x purpose decides:
//
//   basis \ posture      Strict         Standard       Legacy
//   active_consent       all purposes   all purposes   all purposes
//   documented_opt_in    all purposes   all purposes   all purposes
//   legitimate_interest  rejected       operational    operational
//   contract             rejected       service_ops    service_ops
//   legal_obligation     legal_compl.   legal_compl.   legal_compl.
//   undocumented         rejected       rejected       limited-use
//
//   operational  = service_operations, fraud_prevention. Analytics is
//                  deliberately excluded - consent-gated under every posture.
//   limited-use  = service_operations, legal_compliance, fraud_prevention.
//                  Never marketing/personalization/analytics.
// ============================================================================

// Frozen purpose sets. Spelled out literally rather than derived - this is
// the single most audit-sensitive structure in Core, and an auditor should
// be able to read the law without chasing imports.
const ALL_PURPOSES = Object.freeze([
    'marketing', 'personalization', 'analytics',
    'service_operations', 'legal_compliance', 'fraud_prevention',
]);
const OPERATIONAL = Object.freeze(['service_operations', 'fraud_prevention']);
const SERVICE_OPS_ONLY = Object.freeze(['service_operations']);
const LEGAL_COMPLIANCE_ONLY = Object.freeze(['legal_compliance']);
const LIMITED_USE = Object.freeze(['service_operations', 'legal_compliance', 'fraud_prevention']);
const NONE = Object.freeze([]);

// posture -> basis -> purposes permitted for a GRANTED record.
const CAPTURE_RULES = Object.freeze({
    strict: Object.freeze({
        active_consent: ALL_PURPOSES,
        documented_opt_in: ALL_PURPOSES,
        legitimate_interest: NONE,
        contract: NONE,
        legal_obligation: LEGAL_COMPLIANCE_ONLY,
        undocumented: NONE,
    }),
    standard: Object.freeze({
        active_consent: ALL_PURPOSES,
        documented_opt_in: ALL_PURPOSES,
        legitimate_interest: OPERATIONAL,
        contract: SERVICE_OPS_ONLY,
        legal_obligation: LEGAL_COMPLIANCE_ONLY,
        undocumented: NONE,
    }),
    legacy: Object.freeze({
        active_consent: ALL_PURPOSES,
        documented_opt_in: ALL_PURPOSES,
        legitimate_interest: OPERATIONAL,
        contract: SERVICE_OPS_ONLY,
        legal_obligation: LEGAL_COMPLIANCE_ONLY,
        undocumented: LIMITED_USE,
    }),
});

// ----------------------------------------------------------------------------
// evaluateBasis
// ----------------------------------------------------------------------------
//
// May a GRANTED consent record with this basis authorize this purpose under
// this posture? Pure lookup into the rule map.
//
// Unknown posture/basis/purpose values return false (fail closed) rather
// than throwing: the database CHECK constraints make unknown values a bug,
// and the correct behavior for a bug in consent law is to deny, not to 500
// an entire batch.
// ----------------------------------------------------------------------------

function evaluateBasis(posture, basis, purpose) {
    const postureRules = CAPTURE_RULES[posture];
    if (!postureRules) return false;
    const allowedPurposes = postureRules[basis];
    if (!allowedPurposes) return false;
    return allowedPurposes.includes(purpose);
}

// ----------------------------------------------------------------------------
// evaluateCapture
// ----------------------------------------------------------------------------
//
// Applies the full rule map to a set of consent rows matching the implicated
// (identity, purpose, data_category) - the caller has already scoped the
// rows; vendor/channel/jurisdiction vary across them (they are not
// implicated at capture time; per the settled Session 4 ruling they are
// evaluated with DENY-PRECEDENCE here instead).
//
// Rows must be shaped { state, consent_basis, effective_from, record_id }
// (callers map current_consent.source_record_id or consent_records.record_id
// onto record_id, so the evaluator is source-agnostic - the same law applies
// to live capture and to the point-in-time backfill).
//
// Decision order (all fail-closed):
//   1. No rows            -> rejected: no record means NO consent.
//   2. Any denied/withdrawn row -> rejected, even if another row (a
//      different vendor/jurisdiction) is granted: a customer who has denied
//      anyone this purpose over this data plausibly means "stop collecting".
//   3. Granted rows filtered through basis x posture x purpose. None pass ->
//      rejected (basis_insufficient).
//   4. Among passing rows, the one with the LATEST effective_from authorizes
//      (the same supersession rule the current_consent projection uses), so
//      the snapshot cites a deterministic record.
//
// Returns:
//   { allowed: true,  basis, record_id, effective_from }
//   { allowed: false, reason: 'no_consent_record' | 'consent_denied' |
//                             'consent_withdrawn' | 'basis_insufficient',
//     record_id? }   (record_id present when a specific row decided it)
// ----------------------------------------------------------------------------

function evaluateCapture(rows, posture, purpose) {
    if (!rows || rows.length === 0) {
        return { allowed: false, reason: 'no_consent_record' };
    }

    const blocking = rows.find(r => r.state === 'denied' || r.state === 'withdrawn');
    if (blocking) {
        return {
            allowed: false,
            reason: blocking.state === 'denied' ? 'consent_denied' : 'consent_withdrawn',
            record_id: blocking.record_id,
        };
    }

    const passing = rows.filter(r =>
        r.state === 'granted' && evaluateBasis(posture, r.consent_basis, purpose));
    if (passing.length === 0) {
        return { allowed: false, reason: 'basis_insufficient' };
    }

    const authorizing = passing.reduce((best, row) =>
        (new Date(row.effective_from) > new Date(best.effective_from) ? row : best));

    return {
        allowed: true,
        basis: authorizing.consent_basis,
        record_id: authorizing.record_id,
        effective_from: authorizing.effective_from,
    };
}

// ----------------------------------------------------------------------------
// Exports
// ----------------------------------------------------------------------------

module.exports = {
    CAPTURE_RULES,
    evaluateBasis,
    evaluateCapture,
};

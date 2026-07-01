// ============================================================================
// ThreadOS Core - Consent Recording Business Logic
// ============================================================================
//
// Core logic for the consent recording and read APIs: validating consent
// decisions, persisting them into the append-only bitemporal history
// (consent_records) while maintaining the current_consent projection in the
// same transaction, and reading both back (projection + paginated history).
//
// This module owns the "what is a valid consent record and how does it get
// stored" rules. The HTTP layer (src/routes/consent.js) handles
// request/response shaping and calls recordConsent() here.
//
// Bible references:
//   Decision 4:  Tenant scoping - every operation is scoped to the tenant
//                from the verified JWT sub claim; identities are checked to
//                belong to that tenant before any write.
//   Decision 7:  Opinionated gatekeeper - reject bad input with actionable
//                errors; never silently coerce or drop. Vocabulary and
//                temporal rules are validated here at the application layer
//                even though the schema CHECKs would also catch them: a CHECK
//                violation aborts the transaction with an opaque database
//                error, while application validation produces structured,
//                per-field, per-index errors the vertical can act on.
//   Decision 13: Consent dimensions - every record fully specifies
//                purpose x vendor x channel x data_category x jurisdiction.
//   Decision 14: consent_basis records the epistemic status of our knowledge
//                of the decision, distinct from the decision itself.
//   Decision 15: Write-time consent enforcement reads current_consent, so the
//                projection is maintained synchronously in the same
//                transaction as the history insert - it can never disagree
//                with consent_records.
//   Decision 17: Critical path - persistence is synchronous; we return
//                success only after the history and projection are durably
//                written.
// ============================================================================

const { query, withTransaction } = require('./db');
const { validateUuid, validateRequiredString } = require('./validation');
const { scanForPii } = require('./pii');

// ----------------------------------------------------------------------------
// Limits
// ----------------------------------------------------------------------------
//
// A single request may carry one consent record or a batch. Consent decisions
// arrive at human cadence (a preference-center save, a form submission), not
// telemetry cadence, so the cap is lower than the events API's 500: 100 bounds
// worst-case transaction work while comfortably covering a full
// preference-center sweep across every dimension tuple.
// ----------------------------------------------------------------------------

const MAX_BATCH_SIZE = 100;

// History pagination bounds (Step 7 Session 3). 100 covers a typical
// identity's full consent history in one read; 500 bounds the worst case a
// single request can pull without pinning a connection.
const HISTORY_DEFAULT_LIMIT = 100;
const HISTORY_MAX_LIMIT = 500;

// ----------------------------------------------------------------------------
// Controlled vocabularies (Bible Decisions 13, 14)
// ----------------------------------------------------------------------------
//
// These mirror the CHECK constraints on consent_records / current_consent in
// db/schema.sql. Keep the two in lockstep: the schema is the last line of
// defense, this list is what produces actionable errors (Decision 7).
// ----------------------------------------------------------------------------

const PURPOSES = ['marketing', 'personalization', 'analytics',
    'service_operations', 'legal_compliance', 'fraud_prevention'];
const CHANNELS = ['email', 'sms', 'voice', 'push', 'mail', 'in_app'];
const DATA_CATEGORIES = ['behavioral', 'pii', 'location', 'financial', 'health'];
const STATES = ['granted', 'denied', 'withdrawn'];
const CONSENT_BASES = ['active_consent', 'documented_opt_in', 'legitimate_interest',
    'contract', 'legal_obligation', 'undocumented'];
const CAPTURED_VIA = ['web_form', 'email_response', 'phone', 'in_person',
    'imported', 'api_direct', 'paper_form'];

// ISO 3166 jurisdiction: an alpha-2 country code (ISO 3166-1), optionally
// followed by a subdivision suffix (ISO 3166-2), e.g. "US", "US-CA", "DE",
// "GB-SCT". This is a FORMAT check, not a membership check - Core does not
// maintain the country list; it enforces the shape it can legitimately own.
const JURISDICTION_REGEX = /^[A-Z]{2}(-[A-Z0-9]{1,3})?$/;

// ----------------------------------------------------------------------------
// Single-field validators specific to consent
// ----------------------------------------------------------------------------
//
// Each returns { valid, value?, error? } where error is { field, code, message }
// (matching src/lib/validation.js so route handlers can surface a uniform
// `details` array).
// ----------------------------------------------------------------------------

// A required field constrained to a controlled vocabulary.
function validateVocabulary(value, fieldName, allowed) {
    if (value === undefined || value === null || value === '') {
        return {
            valid: false,
            error: { field: fieldName, code: 'missing', message: `${fieldName} is required` },
        };
    }
    if (typeof value !== 'string') {
        return {
            valid: false,
            error: { field: fieldName, code: 'invalid_type', message: `${fieldName} must be a string` },
        };
    }
    if (!allowed.includes(value)) {
        return {
            valid: false,
            error: {
                field: fieldName,
                code: 'invalid_value',
                message: `${fieldName} must be one of: ${allowed.join(', ')}`,
            },
        };
    }
    return { valid: true, value };
}

// Jurisdiction: ISO 3166 format (see JURISDICTION_REGEX). Case-insensitive on
// input, normalized to the canonical uppercase form - the same normalization
// posture as UUID lowercasing (canonical form, not silent coercion of
// substance).
function validateJurisdiction(value, fieldName = 'jurisdiction') {
    if (value === undefined || value === null || value === '') {
        return {
            valid: false,
            error: { field: fieldName, code: 'missing', message: `${fieldName} is required` },
        };
    }
    if (typeof value !== 'string') {
        return {
            valid: false,
            error: { field: fieldName, code: 'invalid_type', message: `${fieldName} must be a string` },
        };
    }
    const normalized = value.trim().toUpperCase();
    if (!JURISDICTION_REGEX.test(normalized)) {
        return {
            valid: false,
            error: {
                field: fieldName,
                code: 'invalid_jurisdiction_format',
                message: `${fieldName} must be an ISO 3166 code: a two-letter country code with an optional subdivision suffix (e.g. "US", "US-CA", "DE")`,
            },
        };
    }
    return { valid: true, value: normalized };
}

// A required ISO 8601 timestamp, normalized to a canonical ISO string.
function validateTimestamp(value, fieldName) {
    if (value === undefined || value === null || value === '') {
        return {
            valid: false,
            error: { field: fieldName, code: 'missing', message: `${fieldName} is required` },
        };
    }
    if (typeof value !== 'string') {
        return {
            valid: false,
            error: { field: fieldName, code: 'invalid_type', message: `${fieldName} must be an ISO 8601 timestamp string` },
        };
    }
    const parsed = new Date(value);
    if (isNaN(parsed.getTime())) {
        return {
            valid: false,
            error: { field: fieldName, code: 'invalid_format', message: `${fieldName} must be a valid ISO 8601 timestamp` },
        };
    }
    return { valid: true, value: parsed.toISOString() };
}

// Optional ISO 8601 timestamp: absent/null means "no end" (open-ended
// validity); if present it must parse.
function validateOptionalTimestamp(value, fieldName) {
    if (value === undefined || value === null || value === '') {
        return { valid: true, value: null };
    }
    return validateTimestamp(value, fieldName);
}

// A required free-text field that must carry no PII (Bible Decision 10 -
// the same rule as event properties: identifying data has exactly one path
// into Core, the identity API). Returns potentially MULTIPLE errors, so its
// failure shape is { valid: false, errors: [...] }.
function validateFreeText(value, fieldName, maxLength) {
    const base = validateRequiredString(value, fieldName, maxLength);
    if (!base.valid) {
        return { valid: false, errors: [base.error] };
    }

    const findings = scanForPii(base.value, fieldName);
    if (findings.length > 0) {
        return {
            valid: false,
            errors: findings.map(finding => ({
                field: finding.path,
                code: 'pii_detected',
                message: `${fieldName} may not contain PII (${finding.type} detected); route identifying data through the identity API`,
            })),
        };
    }

    return { valid: true, value: base.value };
}

// ----------------------------------------------------------------------------
// validateConsentRecord
// ----------------------------------------------------------------------------
//
// Validates and normalizes a single consent record object. Returns:
//   { valid: true, value: <normalized record> }
//   { valid: false, errors: [ { field, code, message, index? }, ... ] }
//
// `index` identifies which record in a batch failed; it's attached by the
// caller (validateConsentRequest) so individual validators stay index-agnostic.
//
// Validation rules (Bible Decisions 7, 13, 14):
//   - identity_id:      required, valid UUID
//   - purpose, channel, data_category, state, consent_basis, captured_via:
//                       required, controlled vocabulary
//   - vendor:           required non-empty string, <= 200 chars
//   - jurisdiction:     required, ISO 3166 format
//   - capture_context:  required non-empty string, <= 2000 chars, no PII
//   - reason:           required non-empty string, <= 2000 chars, no PII
//   - effective_from:   required, valid ISO 8601
//   - effective_until:  optional; if present, valid ISO 8601 and strictly
//                       after effective_from (temporal_invalid otherwise)
// ----------------------------------------------------------------------------

function validateConsentRecord(raw) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
        return {
            valid: false,
            errors: [{ field: 'record', code: 'invalid_type', message: 'each consent record must be a JSON object' }],
        };
    }

    const errors = [];
    const value = {};

    const identityResult = validateUuid(raw.identity_id, 'identity_id');
    if (identityResult.valid) value.identity_id = identityResult.value;
    else errors.push(identityResult.error);

    // The five consent dimensions (Bible Decision 13)
    const purposeResult = validateVocabulary(raw.purpose, 'purpose', PURPOSES);
    if (purposeResult.valid) value.purpose = purposeResult.value;
    else errors.push(purposeResult.error);

    const vendorResult = validateRequiredString(raw.vendor, 'vendor', 200);
    if (vendorResult.valid) value.vendor = vendorResult.value;
    else errors.push(vendorResult.error);

    const channelResult = validateVocabulary(raw.channel, 'channel', CHANNELS);
    if (channelResult.valid) value.channel = channelResult.value;
    else errors.push(channelResult.error);

    const categoryResult = validateVocabulary(raw.data_category, 'data_category', DATA_CATEGORIES);
    if (categoryResult.valid) value.data_category = categoryResult.value;
    else errors.push(categoryResult.error);

    const jurisdictionResult = validateJurisdiction(raw.jurisdiction);
    if (jurisdictionResult.valid) value.jurisdiction = jurisdictionResult.value;
    else errors.push(jurisdictionResult.error);

    // The decision and its epistemic status (Bible Decision 14)
    const stateResult = validateVocabulary(raw.state, 'state', STATES);
    if (stateResult.valid) value.state = stateResult.value;
    else errors.push(stateResult.error);

    const basisResult = validateVocabulary(raw.consent_basis, 'consent_basis', CONSENT_BASES);
    if (basisResult.valid) value.consent_basis = basisResult.value;
    else errors.push(basisResult.error);

    // Capture provenance
    const capturedViaResult = validateVocabulary(raw.captured_via, 'captured_via', CAPTURED_VIA);
    if (capturedViaResult.valid) value.captured_via = capturedViaResult.value;
    else errors.push(capturedViaResult.error);

    const contextResult = validateFreeText(raw.capture_context, 'capture_context', 2000);
    if (contextResult.valid) value.capture_context = contextResult.value;
    else errors.push(...contextResult.errors);

    const reasonResult = validateFreeText(raw.reason, 'reason', 2000);
    if (reasonResult.valid) value.reason = reasonResult.value;
    else errors.push(...reasonResult.errors);

    // Valid time (bitemporal): effective_from required, effective_until
    // optional (null = open-ended).
    const fromResult = validateTimestamp(raw.effective_from, 'effective_from');
    if (fromResult.valid) value.effective_from = fromResult.value;
    else errors.push(fromResult.error);

    const untilResult = validateOptionalTimestamp(raw.effective_until, 'effective_until');
    if (untilResult.valid) value.effective_until = untilResult.value;
    else errors.push(untilResult.error);

    // Temporal validity only makes sense once both endpoints parsed. Strictly
    // after, matching the schema CHECK (effective_until > effective_from): a
    // zero-length validity window is a contradiction, not a decision.
    if (fromResult.valid && untilResult.valid && value.effective_until !== null) {
        if (Date.parse(value.effective_until) <= Date.parse(value.effective_from)) {
            errors.push({
                field: 'effective_until',
                code: 'temporal_invalid',
                message: 'effective_until must be after effective_from',
            });
        }
    }

    if (errors.length > 0) {
        return { valid: false, errors };
    }
    return { valid: true, value };
}

// ----------------------------------------------------------------------------
// validateConsentRequest
// ----------------------------------------------------------------------------
//
// Accepts the raw request body, which may be either a single consent record
// object OR a non-empty array of record objects (mirrors the events API).
// Validates every record and enforces batch-level rules.
//
// Reject-all semantics (Bible Decision 7): if ANY record fails validation, the
// whole request is rejected and we return every error we found, each tagged
// with the index of the record it came from.
//
// A batch MAY contain multiple records for the same dimension tuple: a batch
// is a sequence of decisions, applied in array order, so the last record for
// a tuple wins the current_consent projection (all of them enter the
// history). This is deliberate - unlike events, where a duplicate
// idempotency key is ambiguous and rejected.
//
// Returns:
//   { valid: true, value: [ <normalized records> ] }
//   { valid: false, code?, errors: [ { field, code, message, index? }, ... ] }
// ----------------------------------------------------------------------------

function validateConsentRequest(body) {
    let records;
    if (Array.isArray(body)) {
        records = body;
    } else if (body && typeof body === 'object') {
        records = [body];
    } else {
        // Valid JSON, wrong top-level type (bare string/number/boolean/null).
        // Distinct code so the route can say exactly that (see the events API).
        return {
            valid: false,
            code: 'invalid_body_type',
            errors: [{ field: 'body', code: 'invalid_body_type', message: 'request body must be a JSON object or an array of objects' }],
        };
    }

    if (records.length === 0) {
        return {
            valid: false,
            errors: [{ field: 'body', code: 'empty_batch', message: 'request must contain at least one consent record' }],
        };
    }

    if (records.length > MAX_BATCH_SIZE) {
        return {
            valid: false,
            errors: [{ field: 'body', code: 'batch_too_large', message: `a request may contain at most ${MAX_BATCH_SIZE} consent records` }],
        };
    }

    const errors = [];
    const normalized = [];

    records.forEach((raw, index) => {
        const result = validateConsentRecord(raw);
        if (result.valid) {
            normalized.push(result.value);
        } else {
            for (const err of result.errors) {
                errors.push({ ...err, index });
            }
        }
    });

    if (errors.length > 0) {
        return { valid: false, errors };
    }
    return { valid: true, value: normalized };
}

// ----------------------------------------------------------------------------
// checkIdentities
// ----------------------------------------------------------------------------
//
// Verifies that every identity_id referenced in the batch exists for this
// tenant and is not soft-deleted (Bible Decision 4: structural tenant
// isolation - an identity in another tenant is indistinguishable from one
// that doesn't exist). Pre-checking gives a clean, per-record error instead
// of letting a foreign-key violation abort the transaction with an opaque
// database error.
//
// Returns { ok: true } or { ok: false, errors: [...] }.
// ----------------------------------------------------------------------------

async function checkIdentities(client, tenantId, records) {
    const ids = [...new Set(records.map(r => r.identity_id))];

    const result = await client.query(
        `SELECT id FROM identities
         WHERE tenant_id = $1 AND id = ANY($2) AND deleted_at IS NULL`,
        [tenantId, ids]
    );

    const found = new Set(result.rows.map(r => r.id));

    const errors = [];
    records.forEach((record, index) => {
        if (!found.has(record.identity_id)) {
            errors.push({
                field: 'identity_id',
                code: 'identity_not_found',
                message: `identity_id ${record.identity_id} does not exist for this tenant`,
                index,
            });
        }
    });

    if (errors.length > 0) {
        return { ok: false, errors };
    }
    return { ok: true };
}

// ----------------------------------------------------------------------------
// persistConsentRecords
// ----------------------------------------------------------------------------
//
// Inserts the validated records inside a single transaction, in array order,
// maintaining the current_consent projection alongside the history (Bible
// Decision 15: the projection is written in the SAME transaction, so it can
// never disagree with consent_records).
//
// For each record:
//   1. INSERT into consent_records (append-only history; every record lands
//      here unconditionally).
//   2. Upsert current_consent - but ONLY when the record is currently in
//      effect (effective_from <= now < effective_until). Future-dated and
//      already-expired records enter the history without touching the
//      projection. "Now" is the database clock, the same clock that stamped
//      recorded_at.
//
// The upsert's DO UPDATE additionally requires the incoming effective_from to
// be >= the projected row's. Without this guard, a late-arriving record for
// an OLDER decision (a backfill import, an out-of-order submission) would
// overwrite the projection of a newer decision - the history would be right
// and the projection wrong, exactly what Decision 15 forbids. Ties go to the
// newly recorded row (>=): same valid-time instant, later system-time
// knowledge wins. Within a batch this same rule yields last-record-wins for
// equal effective_from values.
//
// Returns an array of per-record results in input order:
//   { record_id, projection: 'created' | 'updated' | 'none' }
// where projection says what happened to current_consent: a new projection
// row, a superseded one, or no touch (not currently in effect, or guarded
// off as older than the projected decision).
// ----------------------------------------------------------------------------

async function persistConsentRecords(client, tenantId, records) {
    const results = [];

    for (const record of records) {
        const insert = await client.query(
            `INSERT INTO consent_records (
                tenant_id, identity_id, purpose, vendor, channel,
                data_category, jurisdiction, state, consent_basis,
                captured_via, capture_context, reason,
                effective_from, effective_until
             )
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
             RETURNING record_id`,
            [
                tenantId,
                record.identity_id,
                record.purpose,
                record.vendor,
                record.channel,
                record.data_category,
                record.jurisdiction,
                record.state,
                record.consent_basis,
                record.captured_via,
                record.capture_context,
                record.reason,
                record.effective_from,
                record.effective_until,
            ]
        );
        const recordId = insert.rows[0].record_id;

        // The SELECT's WHERE clause is the "currently in effect" test - when it
        // yields no row, nothing is inserted and ON CONFLICT never fires, so
        // future-dated / expired records skip the projection entirely. This IS
        // the started-window guard from the Session 5 ruling: a future-dated
        // record must not displace a currently-valid one and then have the
        // reader filters deny during the gap before its window starts.
        //
        // FUTURE-ACTIVATION POSITION (Session 5 ruling, deliberate): a
        // future-dated record is fully honored in history, point-in-time
        // evaluation, and the backfill - but live-enforcement activation
        // requires its window to have STARTED at write time. A vertical that
        // wants scheduled activation writes the record at activation time;
        // scheduling is module-layer responsibility (modules own workflow,
        // Core owns truth). If verticals demonstrate real demand for
        // Core-side activation, a projection-refresh sweep is the upgrade
        // path.
        //
        // The DO UPDATE guard has two arms:
        //   1. EXCLUDED.effective_from >= incumbent's - the supersession rule:
        //      the decision with the latest valid-time start wins.
        //   2. OR the incumbent's window has LAPSED - an expired row is
        //      semantically "no row" (readers filter it out), so it holds no
        //      supersession rights: a currently-valid record must be able to
        //      replace it even with an earlier effective_from.
        //
        // xmax = 0 distinguishes a fresh insert from a conflict-update: an
        // inserted row has no deleting/locking transaction recorded, an updated
        // row does. (Cast to text because xid has no direct integer equality
        // across all versions.)
        const upsert = await client.query(
            `INSERT INTO current_consent (
                tenant_id, identity_id, purpose, vendor, channel,
                data_category, jurisdiction, state, consent_basis,
                effective_from, effective_until, source_record_id
             )
             SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10::timestamptz, $11::timestamptz, $12
             WHERE $10::timestamptz <= CURRENT_TIMESTAMP
               AND ($11::timestamptz IS NULL OR $11::timestamptz > CURRENT_TIMESTAMP)
             ON CONFLICT (tenant_id, identity_id, purpose, vendor, channel, data_category, jurisdiction)
             DO UPDATE SET
                state = EXCLUDED.state,
                consent_basis = EXCLUDED.consent_basis,
                effective_from = EXCLUDED.effective_from,
                effective_until = EXCLUDED.effective_until,
                source_record_id = EXCLUDED.source_record_id
             WHERE EXCLUDED.effective_from >= current_consent.effective_from
                OR (current_consent.effective_until IS NOT NULL
                    AND current_consent.effective_until <= CURRENT_TIMESTAMP)
             RETURNING (xmax::text = '0') AS was_insert`,
            [
                tenantId,
                record.identity_id,
                record.purpose,
                record.vendor,
                record.channel,
                record.data_category,
                record.jurisdiction,
                record.state,
                record.consent_basis,
                record.effective_from,
                record.effective_until,
                recordId,
            ]
        );

        let projection = 'none';
        if (upsert.rows.length > 0) {
            projection = upsert.rows[0].was_insert ? 'created' : 'updated';
        }

        results.push({ record_id: recordId, projection });
    }

    return results;
}

// ----------------------------------------------------------------------------
// recordConsent
// ----------------------------------------------------------------------------
//
// The orchestrator the HTTP layer calls. Given a verified tenantId (from the
// JWT sub claim - Bible Decision 4, never from the request body) and the raw
// request body, it runs the full pipeline:
//   1. Validate + normalize (shape, vocabularies, jurisdiction, temporal)
//   2. In one transaction: tenant check, identity existence check, persist
//      history + maintain projection
//
// On any failure it returns a rejection with NOTHING persisted - the whole
// batch is rejected atomically (Bible Decision 7: reject-all, no partial
// accept).
//
// Returns:
//   { ok: true, results: [...], created, updated }
//     where created counts new current_consent rows and updated counts
//     superseded ones (records that didn't touch the projection count in
//     neither).
//   { ok: false, code, errors }
//     where code is a machine-readable category the route maps to an HTTP
//     status.
// ----------------------------------------------------------------------------

async function recordConsent(tenantId, body) {
    if (!tenantId) {
        throw new Error('tenantId is required');
    }

    const validation = validateConsentRequest(body);
    if (!validation.valid) {
        return { ok: false, code: validation.code || 'validation_failed', errors: validation.errors };
    }

    const records = validation.value;

    return await withTransaction(async (client) => {
        // Confirm the tenant exists. Without this, a valid JWT for a tenant
        // that doesn't exist would fail as identity_not_found for every record,
        // which misdescribes the real problem. Mirrors the events route.
        const tenantRes = await client.query(
            `SELECT 1 FROM tenants WHERE id = $1 LIMIT 1`,
            [tenantId]
        );
        if (tenantRes.rows.length === 0) {
            return {
                ok: false,
                code: 'tenant_not_found',
                errors: [{ field: 'tenant', code: 'tenant_not_found', message: 'the specified tenant does not exist' }],
            };
        }

        const identityCheck = await checkIdentities(client, tenantId, records);
        if (!identityCheck.ok) {
            // Returning (not throwing) commits an empty transaction, which is
            // fine - nothing was written. Reject-all: no records persisted.
            return { ok: false, code: 'identity_not_found', errors: identityCheck.errors };
        }

        const results = await persistConsentRecords(client, tenantId, records);
        const created = results.filter(r => r.projection === 'created').length;
        const updated = results.filter(r => r.projection === 'updated').length;

        return { ok: true, results, created, updated };
    });
}

// ----------------------------------------------------------------------------
// validateHistoryOptions
// ----------------------------------------------------------------------------
//
// Validates the pagination options for a consent history read (typically the
// raw query-string values, which arrive as strings). Application-layer
// validation per the Gatekeeper Principle: out-of-range values are rejected
// with actionable errors, never silently clamped.
//
//   limit:  optional; integer 1..HISTORY_MAX_LIMIT (default
//           HISTORY_DEFAULT_LIMIT)
//   before: optional; ISO 8601 timestamp; returns only records with
//           recorded_at strictly before it (exclusive cursor)
//
// Returns:
//   { valid: true, value: { limit, before } }
//   { valid: false, errors: [ { field, code, message }, ... ] }
// ----------------------------------------------------------------------------

function validateHistoryOptions(raw = {}) {
    const errors = [];
    const value = { limit: HISTORY_DEFAULT_LIMIT, before: null };

    if (raw.limit !== undefined && raw.limit !== null && raw.limit !== '') {
        // Accept a number or a numeric string (query params arrive as strings).
        // A repeated query param arrives as an array - wrong type, reject.
        const limitNum = (typeof raw.limit === 'string' || typeof raw.limit === 'number')
            ? Number(raw.limit)
            : NaN;
        if (!Number.isInteger(limitNum)) {
            errors.push({ field: 'limit', code: 'invalid_format', message: 'limit must be an integer' });
        } else if (limitNum < 1 || limitNum > HISTORY_MAX_LIMIT) {
            errors.push({
                field: 'limit',
                code: 'invalid_value',
                message: `limit must be between 1 and ${HISTORY_MAX_LIMIT}`,
            });
        } else {
            value.limit = limitNum;
        }
    }

    if (raw.before !== undefined && raw.before !== null && raw.before !== '') {
        const beforeResult = validateTimestamp(raw.before, 'before');
        if (beforeResult.valid) value.before = beforeResult.value;
        else errors.push(beforeResult.error);
    }

    if (errors.length > 0) {
        return { valid: false, errors };
    }
    return { valid: true, value };
}

// ----------------------------------------------------------------------------
// getCurrentConsent
// ----------------------------------------------------------------------------
//
// Reads the current_consent projection for one identity: every dimension
// tuple with a currently-effective decision (Bible Decision 15 - this is the
// same table write-time enforcement reads). No rows means NO consent for
// anything - a valid, meaningful state, not an error.
//
// The window filter (Session 5, finding HIGH-1) makes an expired grant
// invisible the moment its validity window lapses, even though the physical
// row lingers until the next write supersedes it: no visible row for the
// tuple means no consent.
//
// Returns the flat rows in a deterministic dimension order; presentation
// grouping is the HTTP layer's concern.
// ----------------------------------------------------------------------------

async function getCurrentConsent(tenantId, identityId) {
    const result = await query(
        `SELECT purpose, vendor, channel, data_category, jurisdiction,
                state, consent_basis, effective_from, effective_until, source_record_id
         FROM current_consent
         WHERE tenant_id = $1 AND identity_id = $2
           AND effective_from <= CURRENT_TIMESTAMP
           AND (effective_until IS NULL OR effective_until > CURRENT_TIMESTAMP)
         ORDER BY purpose, vendor, channel, data_category, jurisdiction`,
        [tenantId, identityId]
    );
    return result.rows;
}

// ----------------------------------------------------------------------------
// getConsentHistory
// ----------------------------------------------------------------------------
//
// Reads the append-only consent history for one identity, newest first
// (recorded_at DESC - system time, i.e. the order Core learned of decisions).
// record_id DESC as a tiebreaker keeps the order stable when a batch shares
// one recorded_at (all records in a transaction get the same
// CURRENT_TIMESTAMP).
//
// Pagination is an exclusive keyset cursor on recorded_at: pass the oldest
// recorded_at you've seen as `before` to get the next page. We fetch one row
// beyond the limit to report has_more without a second query.
//
// KNOWN LIMIT of the timestamp-only cursor: records sharing the cursor's
// exact recorded_at (same-batch siblings) are excluded along with it, so a
// page boundary that lands inside a batch skips that batch's remaining rows.
// Callers that need batch-safe pagination should raise `limit` instead. The
// fix is a composite (recorded_at, record_id) cursor - deferred until a
// vertical actually pages through histories deep enough to hit it.
//
// Returns { records, has_more }.
// ----------------------------------------------------------------------------

async function getConsentHistory(tenantId, identityId, options = {}) {
    // Defense in depth: the route already rejected out-of-range values with a
    // structured error; this floor/cap only protects direct lib callers.
    const limit = Math.min(options.limit || HISTORY_DEFAULT_LIMIT, HISTORY_MAX_LIMIT);
    const before = options.before || null;

    const result = await query(
        `SELECT record_id, purpose, vendor, channel, data_category, jurisdiction,
                state, consent_basis, captured_via, capture_context, reason,
                effective_from, effective_until, recorded_at
         FROM consent_records
         WHERE tenant_id = $1 AND identity_id = $2
           AND ($3::timestamptz IS NULL OR recorded_at < $3::timestamptz)
         ORDER BY recorded_at DESC, record_id DESC
         LIMIT $4`,
        [tenantId, identityId, before, limit + 1]
    );

    const hasMore = result.rows.length > limit;
    return {
        records: hasMore ? result.rows.slice(0, limit) : result.rows,
        has_more: hasMore,
    };
}

// ----------------------------------------------------------------------------
// readConsent
// ----------------------------------------------------------------------------
//
// The read-path orchestrator the HTTP layer calls. Given a verified tenantId
// (JWT sub claim - Bible Decision 4) and an identity_id, it confirms the
// tenant and identity exist (an identity in another tenant is
// indistinguishable from one that doesn't exist - structural isolation),
// then reads the projection and, optionally, the paginated history.
//
// An existing identity with no consent rows is a SUCCESS with empty results:
// "no record" is the strictest consent state (no consent), not a missing
// resource.
//
// Options: { includeHistory, limit, before } (limit/before pre-validated by
// validateHistoryOptions).
//
// Returns:
//   { ok: true, current: [...], history?: { records, has_more } }
//   { ok: false, code, errors }
// ----------------------------------------------------------------------------

async function readConsent(tenantId, identityId, options = {}) {
    if (!tenantId) {
        throw new Error('tenantId is required');
    }

    const tenantRes = await query(
        `SELECT 1 FROM tenants WHERE id = $1 LIMIT 1`,
        [tenantId]
    );
    if (tenantRes.rows.length === 0) {
        return {
            ok: false,
            code: 'tenant_not_found',
            errors: [{ field: 'tenant', code: 'tenant_not_found', message: 'the specified tenant does not exist' }],
        };
    }

    const identityRes = await query(
        `SELECT 1 FROM identities
         WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL
         LIMIT 1`,
        [tenantId, identityId]
    );
    if (identityRes.rows.length === 0) {
        return {
            ok: false,
            code: 'identity_not_found',
            errors: [{
                field: 'identity_id',
                code: 'identity_not_found',
                message: `identity_id ${identityId} does not exist for this tenant`,
            }],
        };
    }

    const current = await getCurrentConsent(tenantId, identityId);
    const result = { ok: true, current };

    if (options.includeHistory) {
        result.history = await getConsentHistory(tenantId, identityId, options);
    }

    return result;
}

// ----------------------------------------------------------------------------
// Exports
// ----------------------------------------------------------------------------

module.exports = {
    MAX_BATCH_SIZE,
    PURPOSES,
    CHANNELS,
    DATA_CATEGORIES,
    STATES,
    CONSENT_BASES,
    CAPTURED_VIA,
    HISTORY_DEFAULT_LIMIT,
    HISTORY_MAX_LIMIT,
    validateConsentRecord,
    validateConsentRequest,
    validateHistoryOptions,
    checkIdentities,
    persistConsentRecords,
    recordConsent,
    getCurrentConsent,
    getConsentHistory,
    readConsent,
};

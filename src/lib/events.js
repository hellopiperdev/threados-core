// ============================================================================
// ThreadOS Core - Event Capture Business Logic
// ============================================================================
//
// Core logic for the event capture API: validating events, scanning their
// properties for PII, checking the event type registry, and persisting events
// to the database with client-supplied idempotency.
//
// This module owns the "what is a valid event and how does it get stored"
// rules. The HTTP layer (src/routes/events.js) handles request/response
// shaping and calls captureEvents() here.
//
// Bible references:
//   Decision 7:  Opinionated gatekeeper - reject bad input with actionable
//                errors; never silently coerce or drop.
//   Decision 8:  Event schema structure - canonical required fields plus a
//                flexible properties blob; event names must be registered.
//   Decision 9:  Additive-only evolution - we read the registry, we never
//                version event schemas.
//   Decision 10: No PII in event properties - scan for email/phone/SSN and
//                reject. PII has exactly one path into Core: the identity API.
//   Decision 17: Critical path - persistence is synchronous; we return success
//                only after events are durably written.
//   Decision 20: Cookieless-first - device_fingerprint is a label captured with
//                the event, not a cross-session identity mechanism.
// ============================================================================

const { withTransaction } = require('./db');
const { validateUuid, validateOptionalOpaqueId, validateRequiredString } = require('./validation');
const { detectPiiInScalar, scanForPii } = require('./pii');

// ----------------------------------------------------------------------------
// Limits
// ----------------------------------------------------------------------------
//
// A single request may carry one event or a batch. We cap the batch size so a
// single request can't pin a database connection for an unbounded transaction.
// 500 is generous for legitimate batching while bounding worst-case work.
// ----------------------------------------------------------------------------

const MAX_BATCH_SIZE = 500;

// ----------------------------------------------------------------------------
// PII detection (Bible Decision 10)
// ----------------------------------------------------------------------------
//
// The scanner itself lives in src/lib/pii.js (extracted in Step 7 Session 2
// when the consent API became its second caller). Events use it to scan every
// string/number value in an event's properties; any finding rejects the whole
// request. detectPiiInScalar and scanForPii stay on this module's exports so
// existing callers and tests are unaffected by the extraction.
// ----------------------------------------------------------------------------
// Single-field validators specific to events
// ----------------------------------------------------------------------------
//
// Each returns { valid, value?, error? } where error is { field, code, message }
// (matching the shape used in src/lib/validation.js so route handlers can
// surface a uniform `details` array).
// ----------------------------------------------------------------------------

// Optional UUID: absent is fine; if present it must be a valid UUID.
function validateOptionalUuid(value, fieldName) {
    if (value === undefined || value === null || value === '') {
        return { valid: true, value: null };
    }
    const result = validateUuid(value, fieldName);
    if (!result.valid) {
        return { valid: false, error: result.error };
    }
    return { valid: true, value: result.value };
}

// event_timestamp must be a parseable ISO 8601 timestamp. We normalize to an
// ISO string so the database always stores a canonical TIMESTAMPTZ value.
function validateEventTimestamp(value, fieldName = 'event_timestamp') {
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

// ----------------------------------------------------------------------------
// validateEvent
// ----------------------------------------------------------------------------
//
// Validates and normalizes a single event object. Returns:
//   { valid: true, value: <normalized event> }
//   { valid: false, errors: [ { field, code, message, index? }, ... ] }
//
// `index` identifies which event in a batch failed; it's attached by the
// caller (validateEventsRequest) so individual validators stay index-agnostic.
//
// Validation rules (Bible Decisions 7, 8, 10):
//   - event_id:        required, valid UUID (client idempotency key)
//   - event_name:      required non-empty string
//   - event_category:  required non-empty string
//   - source_type:     required non-empty string
//   - event_timestamp: required, valid ISO 8601
//   - identity_id / session_id / device_fingerprint: at least one required
//   - source_id:       optional string
//   - properties:      optional object, must contain no PII
// ----------------------------------------------------------------------------

function validateEvent(raw) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
        return {
            valid: false,
            errors: [{ field: 'event', code: 'invalid_type', message: 'each event must be a JSON object' }],
        };
    }

    const errors = [];
    const value = {};

    const eventIdResult = validateUuid(raw.event_id, 'event_id');
    if (eventIdResult.valid) value.event_id = eventIdResult.value;
    else errors.push(eventIdResult.error);

    const nameResult = validateRequiredString(raw.event_name, 'event_name', 100);
    if (nameResult.valid) value.event_name = nameResult.value;
    else errors.push(nameResult.error);

    const categoryResult = validateRequiredString(raw.event_category, 'event_category', 50);
    if (categoryResult.valid) value.event_category = categoryResult.value;
    else errors.push(categoryResult.error);

    const sourceTypeResult = validateRequiredString(raw.source_type, 'source_type', 50);
    if (sourceTypeResult.valid) value.source_type = sourceTypeResult.value;
    else errors.push(sourceTypeResult.error);

    const timestampResult = validateEventTimestamp(raw.event_timestamp);
    if (timestampResult.valid) value.event_timestamp = timestampResult.value;
    else errors.push(timestampResult.error);

    // Optional source_id
    if (raw.source_id === undefined || raw.source_id === null || raw.source_id === '') {
        value.source_id = null;
    } else if (typeof raw.source_id !== 'string') {
        errors.push({ field: 'source_id', code: 'invalid_type', message: 'source_id must be a string' });
    } else if (raw.source_id.length > 100) {
        errors.push({ field: 'source_id', code: 'too_long', message: 'source_id must be 100 characters or fewer' });
    } else {
        value.source_id = raw.source_id;
    }

    // Identifiers: at least one of identity_id, session_id, device_fingerprint.
    const identityResult = validateOptionalUuid(raw.identity_id, 'identity_id');
    if (identityResult.valid) value.identity_id = identityResult.value;
    else errors.push(identityResult.error);

    // session_id and device_fingerprint are opaque identifiers minted by
    // external systems (Express/Rails/SDK session stores, device fingerprinting
    // libraries). Core does not own their format, so it cannot demand a UUID or
    // any other shape - it only enforces what it legitimately owns: a non-empty,
    // length-bounded string free of control characters.
    const sessionResult = validateOptionalOpaqueId(raw.session_id, 'session_id');
    if (sessionResult.valid) value.session_id = sessionResult.value;
    else errors.push(sessionResult.error);

    const fingerprintResult = validateOptionalOpaqueId(raw.device_fingerprint, 'device_fingerprint');
    if (fingerprintResult.valid) value.device_fingerprint = fingerprintResult.value;
    else errors.push(fingerprintResult.error);

    // The "at least one identifier" check only makes sense once the individual
    // identifier fields have passed their own type checks.
    const identifierFieldsValid =
        identityResult.valid && sessionResult.valid && fingerprintResult.valid;

    if (identifierFieldsValid) {
        const hasIdentifier =
            value.identity_id || value.session_id || value.device_fingerprint;
        if (!hasIdentifier) {
            errors.push({
                field: 'event',
                code: 'missing_identifier',
                message: 'at least one of identity_id, session_id, or device_fingerprint is required',
            });
        }
    }

    // Properties: optional object, scanned for PII (Bible Decision 10).
    if (raw.properties === undefined || raw.properties === null) {
        value.properties = {};
    } else if (typeof raw.properties !== 'object' || Array.isArray(raw.properties)) {
        errors.push({ field: 'properties', code: 'invalid_type', message: 'properties must be a JSON object' });
    } else {
        value.properties = raw.properties;
        const piiFindings = scanForPii(raw.properties);
        for (const finding of piiFindings) {
            errors.push({
                field: finding.path,
                code: 'pii_detected',
                message: `properties may not contain PII (${finding.type} detected at ${finding.path}); route identifying data through the identity API`,
            });
        }
    }

    if (errors.length > 0) {
        return { valid: false, errors };
    }
    return { valid: true, value };
}

// ----------------------------------------------------------------------------
// validateEventsRequest
// ----------------------------------------------------------------------------
//
// Accepts the raw request body, which may be either a single event object OR a
// non-empty array of event objects (Step 6 settled design). Validates every
// event and enforces batch-level rules.
//
// Reject-all semantics (Bible Decision 7): if ANY event fails validation, the
// whole request is rejected and we return every error we found, each tagged
// with the index of the event it came from.
//
// Returns:
//   { valid: true, value: [ <normalized events> ] }
//   { valid: false, errors: [ { field, code, message, index? }, ... ] }
// ----------------------------------------------------------------------------

function validateEventsRequest(body) {
    // Normalize to an array. Remember whether the caller sent a single object
    // so callers that care about response shaping can ask; here we only need
    // the array form.
    let events;
    if (Array.isArray(body)) {
        events = body;
    } else if (body && typeof body === 'object') {
        events = [body];
    } else {
        // The body parsed as valid JSON but its top-level type is neither an
        // object nor an array (e.g. a bare string, number, boolean, or null).
        // This is distinct from "not valid JSON": the bytes were fine, the shape
        // is wrong. We surface a dedicated code so the route can say exactly that
        // rather than mislabeling it invalid_json.
        return {
            valid: false,
            code: 'invalid_body_type',
            errors: [{ field: 'body', code: 'invalid_body_type', message: 'request body must be a JSON object or an array of objects' }],
        };
    }

    if (events.length === 0) {
        return {
            valid: false,
            errors: [{ field: 'body', code: 'empty_batch', message: 'request must contain at least one event' }],
        };
    }

    if (events.length > MAX_BATCH_SIZE) {
        return {
            valid: false,
            errors: [{ field: 'body', code: 'batch_too_large', message: `a request may contain at most ${MAX_BATCH_SIZE} events` }],
        };
    }

    const errors = [];
    const normalized = [];

    events.forEach((raw, index) => {
        const result = validateEvent(raw);
        if (result.valid) {
            normalized.push(result.value);
        } else {
            for (const err of result.errors) {
                errors.push({ ...err, index });
            }
        }
    });

    // Intra-batch duplicate event_id is ambiguous (which one wins?), so we
    // reject rather than silently dropping one. Only meaningful once each
    // event's event_id passed its own UUID check.
    if (errors.length === 0) {
        const seen = new Map();
        normalized.forEach((evt, index) => {
            if (seen.has(evt.event_id)) {
                errors.push({
                    field: 'event_id',
                    code: 'duplicate_event_id_in_batch',
                    message: `event_id ${evt.event_id} appears more than once in this batch`,
                    index,
                });
            } else {
                seen.set(evt.event_id, index);
            }
        });
    }

    if (errors.length > 0) {
        return { valid: false, errors };
    }
    return { valid: true, value: normalized };
}

// ----------------------------------------------------------------------------
// checkRegistry
// ----------------------------------------------------------------------------
//
// Verifies that every (event_name, event_category) pair in the batch is
// registered and active for this tenant (Bible Decision 8). An event whose
// name isn't registered, or whose category doesn't match the registered
// category, is rejected.
//
// Runs as a single query over the distinct names in the batch rather than one
// query per event.
//
// Returns { ok: true } or { ok: false, errors: [...] } with one error per
// offending event index.
// ----------------------------------------------------------------------------

async function checkRegistry(client, tenantId, events) {
    const names = [...new Set(events.map(e => e.event_name))];

    const result = await client.query(
        `SELECT event_name, event_category
         FROM event_type_registry
         WHERE tenant_id = $1 AND event_name = ANY($2) AND is_active = true`,
        [tenantId, names]
    );

    // Map of registered event_name -> its registered category.
    const registered = new Map();
    for (const row of result.rows) {
        registered.set(row.event_name, row.event_category);
    }

    const errors = [];
    events.forEach((evt, index) => {
        if (!registered.has(evt.event_name)) {
            errors.push({
                field: 'event_name',
                code: 'unregistered_event',
                message: `event_name "${evt.event_name}" is not a registered event type for this tenant`,
                index,
            });
            return;
        }
        const registeredCategory = registered.get(evt.event_name);
        if (registeredCategory !== evt.event_category) {
            errors.push({
                field: 'event_category',
                code: 'event_category_mismatch',
                message: `event_name "${evt.event_name}" is registered under category "${registeredCategory}", not "${evt.event_category}"`,
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
// checkIdentities
// ----------------------------------------------------------------------------
//
// Verifies that every identity_id referenced in the batch exists for this
// tenant and is not soft-deleted. Pre-checking gives a clean, per-event error
// instead of letting a foreign-key violation abort the whole transaction with
// an opaque database error.
//
// Returns { ok: true } or { ok: false, errors: [...] }.
// ----------------------------------------------------------------------------

async function checkIdentities(client, tenantId, events) {
    const ids = [...new Set(events.map(e => e.identity_id).filter(Boolean))];
    if (ids.length === 0) {
        return { ok: true };
    }

    const result = await client.query(
        `SELECT id FROM identities
         WHERE tenant_id = $1 AND id = ANY($2) AND deleted_at IS NULL`,
        [tenantId, ids]
    );

    const found = new Set(result.rows.map(r => r.id));

    const errors = [];
    events.forEach((evt, index) => {
        if (evt.identity_id && !found.has(evt.identity_id)) {
            errors.push({
                field: 'identity_id',
                code: 'identity_not_found',
                message: `identity_id ${evt.identity_id} does not exist for this tenant`,
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
// Consent snapshot placeholder (Bible Decision 15)
// ----------------------------------------------------------------------------
//
// The events table requires a non-null consent_snapshot, but write-time consent
// enforcement is Step 7. Until the consent API exists we persist an explicit
// "not evaluated" marker rather than a fake granted/denied decision, so that
// when consent enforcement lands these events are clearly distinguishable as
// pre-enforcement. This is deferred complexity, not a durable choice: Step 7
// replaces this with a real snapshot.
//
// TODO(Step 7 - consent): When write-time consent enforcement lands, this
// placeholder must be (1) replaced with a real evaluated snapshot for new
// events, AND (2) backfilled for the historical events written during Step 6.
// Those rows are findable by consent_snapshot->>'status' = 'not_evaluated';
// Step 7 must decide their disposition (re-evaluate against consent captured
// later, quarantine, or expire) rather than silently leaving them unenforced.
// ----------------------------------------------------------------------------

const CONSENT_NOT_EVALUATED = { status: 'not_evaluated', reason: 'consent_enforcement_pending_step_7' };

// ----------------------------------------------------------------------------
// persistEvents
// ----------------------------------------------------------------------------
//
// Inserts the validated, registry-checked events inside a single transaction
// (Bible Decision 17: synchronous persistence, all-or-nothing for the batch).
//
// Idempotency (settled Step 6 design): the insert uses
// ON CONFLICT (tenant_id, event_id) DO NOTHING. A row that already existed is
// reported as a duplicate (no-op success); a freshly inserted row is reported
// as created. We learn which happened from RETURNING - a conflicting row
// returns nothing.
//
// Returns an array of per-event results in input order:
//   { event_id, status: 'created' | 'duplicate', id? }
// where `id` is Core's generated primary key for newly created events.
// ----------------------------------------------------------------------------

async function persistEvents(client, tenantId, events) {
    const results = [];

    for (const evt of events) {
        const insert = await client.query(
            `INSERT INTO events (
                tenant_id, event_id, identity_id, session_id, device_fingerprint,
                source_type, source_id, event_name, event_category,
                properties, consent_snapshot, event_timestamp, validation_status
             )
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'valid')
             ON CONFLICT (tenant_id, event_id) WHERE event_id IS NOT NULL DO NOTHING
             RETURNING id`,
            [
                tenantId,
                evt.event_id,
                evt.identity_id,
                evt.session_id,
                evt.device_fingerprint,
                evt.source_type,
                evt.source_id,
                evt.event_name,
                evt.event_category,
                evt.properties,
                CONSENT_NOT_EVALUATED,
                evt.event_timestamp,
            ]
        );

        if (insert.rows.length > 0) {
            results.push({ event_id: evt.event_id, status: 'created', id: insert.rows[0].id });
        } else {
            results.push({ event_id: evt.event_id, status: 'duplicate' });
        }
    }

    return results;
}

// ----------------------------------------------------------------------------
// captureEvents
// ----------------------------------------------------------------------------
//
// The orchestrator the HTTP layer calls. Given a verified tenantId and the raw
// request body, it runs the full pipeline:
//   1. Validate + normalize (shape, identifiers, PII)
//   2. In one transaction: registry check, identity existence check, persist
//
// On a validation/registry/identity failure it returns a rejection WITHOUT
// touching the database (or rolling back), so the whole batch is rejected
// atomically (Bible Decision 7: reject-all, no partial accept).
//
// Returns:
//   { ok: true, results: [...], created, duplicates }
//   { ok: false, code, errors }
//
// where `code` is a machine-readable category the route maps to an HTTP error.
// ----------------------------------------------------------------------------

async function captureEvents(tenantId, body) {
    if (!tenantId) {
        throw new Error('tenantId is required');
    }

    const validation = validateEventsRequest(body);
    if (!validation.valid) {
        // A wrong top-level type carries its own code (invalid_body_type); every
        // other shape failure is a generic validation_failed.
        return { ok: false, code: validation.code || 'validation_failed', errors: validation.errors };
    }

    const events = validation.value;

    return await withTransaction(async (client) => {
        // Confirm the tenant exists. Without this, a valid JWT for a tenant that
        // doesn't exist would fail later as "unregistered_event" (its registry
        // is empty), which misdescribes the real problem. Mirrors the identity
        // route's tenant_not_found behavior.
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

        const registryCheck = await checkRegistry(client, tenantId, events);
        if (!registryCheck.ok) {
            // Returning (not throwing) commits an empty transaction, which is
            // fine - nothing was written. Reject-all: no events persisted.
            return { ok: false, code: 'unregistered_event', errors: registryCheck.errors };
        }

        const identityCheck = await checkIdentities(client, tenantId, events);
        if (!identityCheck.ok) {
            return { ok: false, code: 'identity_not_found', errors: identityCheck.errors };
        }

        const results = await persistEvents(client, tenantId, events);
        const created = results.filter(r => r.status === 'created').length;
        const duplicates = results.filter(r => r.status === 'duplicate').length;

        return { ok: true, results, created, duplicates };
    });
}

// ----------------------------------------------------------------------------
// Exports
// ----------------------------------------------------------------------------

module.exports = {
    MAX_BATCH_SIZE,
    scanForPii,
    detectPiiInScalar,
    validateEvent,
    validateEventsRequest,
    checkRegistry,
    checkIdentities,
    persistEvents,
    captureEvents,
    CONSENT_NOT_EVALUATED,
};

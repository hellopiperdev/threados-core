// ============================================================================
// ThreadOS Core - Event Route Handlers
// ============================================================================
//
// HTTP endpoint for event capture.
//
// This module owns HTTP concerns only: enforcing Content-Type, requiring a
// signed request, calling the event capture business logic, and mapping its
// result onto an HTTP status + structured body. All real work happens in
// src/lib/events.js.
//
// Bible references:
//   Decision 7:  Opinionated gatekeeper - reject bad input with actionable errors
//   Decision 8:  Event schema structure (registered event names)
//   Decision 10: No PII in event properties
//   Decision 17: Synchronous persistence - 2xx only after durable write
//   Decision 18: Service-to-service authentication (requireSignedRequest)
// ============================================================================

const express = require('express');
const { captureEvents } = require('../lib/events');
const { requireSignedRequest } = require('../middleware/auth');

const router = express.Router();

// ----------------------------------------------------------------------------
// Content-Type check middleware
// ----------------------------------------------------------------------------
//
// Same rationale as the identity route: without this, Express silently ignores
// non-JSON bodies and validation reports a misleading "missing field" error
// instead of the actual problem (wrong content type).
// ----------------------------------------------------------------------------

function requireJsonContent(req, res, next) {
    const contentType = req.header('Content-Type') || '';

    if (!contentType.toLowerCase().includes('application/json')) {
        return res.status(415).json({
            error: {
                code: 'unsupported_media_type',
                message: 'Content-Type must be application/json',
            },
        });
    }

    next();
}

// ----------------------------------------------------------------------------
// Map a captureEvents() rejection code to an HTTP status.
// ----------------------------------------------------------------------------
//
// THE STATUS RULE (deliberate, Core-wide convention - do not re-derive):
//
//   400  Unprocessable / malformed payload. The request body itself is wrong:
//        missing/ill-typed fields, bad timestamp, PII in properties. The client
//        can fix it by correcting the bytes it sent.   -> validation_failed
//
//   404  The TENANT addressed by the JWT `sub` claim does not exist. This is the
//        single "the addressed tenant is missing" case, and it mirrors the
//        identity route's tenant_not_found. 404 is reserved EXCLUSIVELY for the
//        tenant; nothing else returns 404.            -> tenant_not_found
//
//   422  Every OTHER referenced entity that doesn't exist or violates a registry
//        constraint, evaluated WITHIN an authenticated, existing-tenant context:
//        an unregistered event type, an event_category that contradicts the
//        registration, or an identity_id that isn't in this tenant. The payload
//        is well-formed; what it points at is the problem.
//                          -> unregistered_event, identity_not_found (+ mismatch)
//
// In short: 404 == "the tenant in your token is gone", 422 == "your well-formed
// request references something else that isn't there / isn't allowed", 400 ==
// "your payload is malformed". Keep new rejection codes on this rule.
// ----------------------------------------------------------------------------

function statusForRejection(code) {
    switch (code) {
        case 'tenant_not_found':
            return 404;
        case 'unregistered_event':
        case 'identity_not_found':
            return 422;
        case 'validation_failed':
        default:
            return 400;
    }
}

// ----------------------------------------------------------------------------
// POST /api/v1/events
// ----------------------------------------------------------------------------
//
// Captures one event or a batch of events.
//
// Request body: either a single event object OR an array of event objects.
//
// Event object:
//   {
//     "event_id": "uuid",            (required, client idempotency key)
//     "event_name": "page_viewed",   (required, must be registered)
//     "event_category": "engagement",(required, must match the registration)
//     "source_type": "web",          (required)
//     "event_timestamp": "ISO 8601", (required)
//     "identity_id": "uuid",         (optional)
//     "session_id": "uuid",          (optional)
//     "device_fingerprint": "string",(optional)
//     "source_id": "string",         (optional)
//     "properties": { ... }          (optional, no PII allowed)
//   }
// At least one of identity_id / session_id / device_fingerprint is required.
//
// Success response (201 if any event was newly created, 200 if all were
// idempotent duplicates):
//   {
//     "results": [ { "event_id": "uuid", "status": "created"|"duplicate", "id"? } ],
//     "created": <int>,
//     "duplicates": <int>
//   }
//
// Error response:
//   {
//     "error": {
//       "code": "...",
//       "message": "...",
//       "details": [ { field, code, message, index? }, ... ]
//     }
//   }
// ----------------------------------------------------------------------------

router.post('/', requireJsonContent, requireSignedRequest, async (req, res, next) => {
    try {
        const result = await captureEvents(req.tenantId, req.body);

        if (!result.ok) {
            return res.status(statusForRejection(result.code)).json({
                error: {
                    code: result.code,
                    message: 'event capture rejected',
                    details: result.errors,
                },
            });
        }

        // 201 when at least one event was newly persisted; 200 when every event
        // was an idempotent duplicate (a no-op success per the settled design).
        const statusCode = result.created > 0 ? 201 : 200;

        return res.status(statusCode).json({
            results: result.results,
            created: result.created,
            duplicates: result.duplicates,
        });

    } catch (err) {
        // Database is unreachable. Temporary infrastructure issue, not a request
        // problem - tell clients/monitoring to retry. (Same handling as the
        // identity route.)
        if (err.code === 'ECONNREFUSED' || err.code === 'ETIMEDOUT' || err.code === 'ENOTFOUND') {
            console.error('Database connection failed:', err.code);
            return res.status(503).json({
                error: {
                    code: 'service_unavailable',
                    message: 'database temporarily unavailable, please retry',
                },
            });
        }

        next(err);
    }
});

module.exports = router;

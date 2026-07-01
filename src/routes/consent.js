// ============================================================================
// ThreadOS Core - Consent Route Handlers
// ============================================================================
//
// HTTP endpoint for recording consent decisions.
//
// This module owns HTTP concerns only: enforcing Content-Type, requiring a
// signed request, calling the consent business logic, and mapping its result
// onto an HTTP status + structured body. All real work happens in
// src/lib/consent.js.
//
// Bible references:
//   Decision 4:  Tenant scoping - the tenant comes from the verified JWT sub
//                claim (req.tenantId, set by requireSignedRequest), never
//                from the request body.
//   Decision 7:  Opinionated gatekeeper - reject bad input with actionable
//                errors; reject-all batch semantics.
//   Decision 13: Consent dimensions (purpose x vendor x channel x
//                data_category x jurisdiction).
//   Decision 15: current_consent projection maintained in the same
//                transaction as the history insert.
//   Decision 17: Synchronous persistence - 2xx only after durable write.
//   Decision 18: Service-to-service authentication (requireSignedRequest).
// ============================================================================

const express = require('express');
const { recordConsent } = require('../lib/consent');
const { requireSignedRequest } = require('../middleware/auth');

const router = express.Router();

// ----------------------------------------------------------------------------
// Content-Type check middleware
// ----------------------------------------------------------------------------
//
// Same rationale as the identity and events routes: without this, Express
// silently ignores non-JSON bodies and validation reports a misleading
// "missing field" error instead of the actual problem (wrong content type).
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
// Map a recordConsent() rejection code to an HTTP status.
// ----------------------------------------------------------------------------
//
// Follows THE STATUS RULE established in src/routes/events.js (do not
// re-derive): 400 = malformed payload, 404 = the tenant addressed by the JWT
// sub claim does not exist (404 is reserved EXCLUSIVELY for the tenant),
// 422 = a well-formed request references something else that isn't there
// (here: an identity_id not in this tenant).
// ----------------------------------------------------------------------------

function statusForRejection(code) {
    switch (code) {
        case 'tenant_not_found':
            return 404;
        case 'identity_not_found':
            return 422;
        case 'validation_failed':
        case 'invalid_body_type':
        default:
            return 400;
    }
}

// ----------------------------------------------------------------------------
// POST /api/v1/consent
// ----------------------------------------------------------------------------
//
// Records one consent decision or a batch (max 100). Each record enters the
// append-only consent_records history; records currently in effect also
// upsert the current_consent projection in the same transaction.
//
// Request body: either a single record object OR an array of record objects.
//
// Record object:
//   {
//     "identity_id": "uuid",           (required, Core-owned UUID)
//     "purpose": "marketing",          (required, controlled vocabulary)
//     "vendor": "acme_dms",            (required, <= 200 chars)
//     "channel": "email",              (required, controlled vocabulary)
//     "data_category": "behavioral",   (required, controlled vocabulary)
//     "jurisdiction": "US-CA",         (required, ISO 3166 format)
//     "state": "granted",              (required: granted|denied|withdrawn)
//     "consent_basis": "active_consent", (required, controlled vocabulary)
//     "captured_via": "web_form",      (required, controlled vocabulary)
//     "capture_context": "...",        (required, <= 2000 chars, no PII)
//     "reason": "...",                 (required, <= 2000 chars, no PII)
//     "effective_from": "ISO 8601",    (required)
//     "effective_until": "ISO 8601"    (optional, null = open-ended)
//   }
//
// A batch may contain multiple records for the same dimension tuple; they
// apply in array order, so the last one wins the projection (all enter the
// history).
//
// Success response (201 - consent records are append-only, so a successful
// request always creates history rows):
//   {
//     "results": [ { "record_id": "uuid", "projection": "created"|"updated"|"none" } ],
//     "created": <int>,   // new current_consent rows
//     "updated": <int>    // superseded current_consent rows
//   }
// "none" means the record entered the history without touching the
// projection (future-dated, already expired, or older than the currently
// projected decision).
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
        const result = await recordConsent(req.tenantId, req.body);

        if (!result.ok) {
            return res.status(statusForRejection(result.code)).json({
                error: {
                    code: result.code,
                    message: 'consent recording rejected',
                    details: result.errors,
                },
            });
        }

        return res.status(201).json({
            results: result.results,
            created: result.created,
            updated: result.updated,
        });

    } catch (err) {
        // Database is unreachable. Temporary infrastructure issue, not a
        // request problem - tell clients/monitoring to retry. (Same handling
        // as the identity and events routes.)
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

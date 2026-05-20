// ============================================================================
// ThreadOS Core - Identity Route Handlers
// ============================================================================
//
// HTTP endpoints for identity operations.
//
// This module owns HTTP concerns only: parsing requests, validating input
// shape, calling the appropriate business logic, and shaping responses.
// All real work happens in src/lib/identity.js.
//
// Bible references:
//   Decision 7: Opinionated gatekeeper - reject bad input with actionable errors
//   Decision 18: Service-to-service authentication
// ============================================================================

const express = require('express');
const { resolveIdentity } = require('../lib/identity');
const {
    validateIdentityHashRequest,
    validateUuid,
} = require('../lib/validation');

const router = express.Router();

// ----------------------------------------------------------------------------
// Tenant context middleware
// ----------------------------------------------------------------------------
//
// Extracts the tenant_id from request headers and attaches it to req.tenantId.
//
// TODO (tracked in ClickUp - Urgent): Replace this with JWT validation.
// The production approach is: vertical signs a JWT with tenant_id claim,
// Core verifies signature, extracts tenant_id from verified claim.
// Bible Decision 18. Current header-based approach is for development only
// and is explicitly insecure for production - anyone can claim any tenant_id.
// ----------------------------------------------------------------------------

function tenantContext(req, res, next) {
    const tenantId = req.header('X-Tenant-Id');

    const validation = validateUuid(tenantId, 'X-Tenant-Id');

    if (!validation.valid) {
        return res.status(400).json({
            error: {
                code: 'invalid_tenant',
                message: 'X-Tenant-Id header is required and must be a valid UUID',
                details: [validation.error],
            },
        });
    }

    req.tenantId = validation.value;
    next();
}

// ----------------------------------------------------------------------------
// Content-Type check middleware
// ----------------------------------------------------------------------------
//
// Ensures POST requests with a body have Content-Type: application/json.
// Without this check, Express silently ignores non-JSON bodies and our
// validation reports the misleading "missing_identifier" instead of the
// actual problem (wrong content type).
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
// POST /api/v1/identity/hash
// ----------------------------------------------------------------------------
//
// Hashes PII and returns the resulting identity record.
//
// If an identity already exists for the given tenant + identifiers, returns
// the existing one. Otherwise creates a new identity.
//
// Request body:
//   {
//     "email": "jane@example.com",   (optional, but at least one identifier required)
//     "phone": "555-1234",           (optional, but at least one identifier required)
//     "name": "Jane Doe"             (optional)
//   }
//
// Required headers:
//   X-Tenant-Id: <uuid>              (provisional; will become JWT)
//
// Success response (200):
//   {
//     "identity": {
//       "id": "uuid",
//       "display_email": "j***@example.com",
//       "display_phone": "***-***-1234",
//       "display_name": "Jane",
//       "created": true
//     }
//   }
//
// Error response (400):
//   {
//     "error": {
//       "code": "validation_failed",
//       "message": "...",
//       "details": [{ field, code, message }, ...]
//     }
//   }
// ----------------------------------------------------------------------------

router.post('/hash', requireJsonContent, tenantContext, async (req, res, next) => {
    try {
        // Validate request body shape
        const validation = validateIdentityHashRequest(req.body);

        if (!validation.valid) {
            return res.status(400).json({
                error: {
                    code: 'validation_failed',
                    message: 'request validation failed',
                    details: validation.errors,
                },
            });
        }

        // Resolve (find or create) the identity
        const { identity, created } = await resolveIdentity(
            req.tenantId,
            validation.value
        );

        // Verify the tenant actually exists. If the tenant_id was syntactically
        // valid but doesn't correspond to a real tenant, resolveIdentity will
        // have failed with a foreign key error - but it's clearer to fail with
        // a structured error than to let a database error bubble up.
        // (We catch this case in the error handler below for now.)

        // Build the sanitized response
        return res.status(created ? 201 : 200).json({
            identity: {
                id: identity.id,
                display_email: identity.display_email,
                display_phone: identity.display_phone,
                display_name: identity.display_name,
                created: created,
            },
        });

    } catch (err) {
        // Foreign key violation = tenant doesn't exist
        if (err.code === '23503' && err.constraint && err.constraint.includes('tenant')) {
            return res.status(404).json({
                error: {
                    code: 'tenant_not_found',
                    message: 'the specified tenant does not exist',
                },
            });
        }

        // Database is unreachable (ECONNREFUSED, ETIMEDOUT, etc.). This is a
        // temporary service issue, not a request problem. 503 tells clients
        // (and monitoring) to retry rather than treating it as a permanent
        // server bug.
        if (err.code === 'ECONNREFUSED' || err.code === 'ETIMEDOUT' || err.code === 'ENOTFOUND') {
            console.error('Database connection failed:', err.code);
            return res.status(503).json({
                error: {
                    code: 'service_unavailable',
                    message: 'database temporarily unavailable, please retry',
                },
            });
        }

        // Pass other errors to the global error handler
        next(err);
    }
});

module.exports = router;
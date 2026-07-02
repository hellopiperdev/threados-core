// ============================================================================
// ThreadOS Core - Identity Repository
// ============================================================================
//
// Functions for creating and retrieving identity records.
//
// This module sits between the HTTP layer (Session 4) and the database
// layer. HTTP handlers call these functions; these functions handle hashing,
// validation, and database access.
//
// Bible references:
//   Decision 1: HMAC-SHA256 hashing (delegated to lib/hashing)
//   Decision 2: Deterministic matching for MVP
//   Decision 4: Tenant-scoped identity (every function takes tenantId)
//   Decision 5: Abstract Core - this module knows nothing about verticals
// ============================================================================

const { query, withTransaction } = require('./db');
const { writeAudit, auditIdentityHashed } = require('./audit');
const {
    hashPII,
    normalizePhone,
    generateResolutionKey,
    sanitizeEmail,
    sanitizePhone,
} = require('./hashing');

// ----------------------------------------------------------------------------
// findIdentityByHash
// ----------------------------------------------------------------------------
//
// Looks up an existing identity using already-hashed identifiers.
// Returns the identity record, or null if no match.
//
// Lookup strategy: tries the resolution key first (fastest path when we have
// both identifiers), then falls back to individual hash lookups.
//
// At least one of emailHash or phoneHash must be provided.
// ----------------------------------------------------------------------------

async function findIdentityByHash(tenantId, emailHash, phoneHash) {
    if (!tenantId) {
        throw new Error('tenantId is required');
    }
    if (!emailHash && !phoneHash) {
        throw new Error('At least one of emailHash or phoneHash is required');
    }

    // Strategy 1: if we have both hashes, look up by resolution key.
    // This is the most precise match.
    if (emailHash && phoneHash) {
        const resolutionKey = generateResolutionKey(emailHash, phoneHash);
        const result = await query(
            `SELECT * FROM identities
             WHERE tenant_id = $1 AND resolution_key = $2 AND deleted_at IS NULL
             LIMIT 1`,
            [tenantId, resolutionKey]
        );
        if (result.rows.length > 0) {
            return result.rows[0];
        }
    }

    // Strategy 2: look up by email hash alone
    if (emailHash) {
        const result = await query(
            `SELECT * FROM identities
             WHERE tenant_id = $1 AND email_hash = $2 AND deleted_at IS NULL
             LIMIT 1`,
            [tenantId, emailHash]
        );
        if (result.rows.length > 0) {
            return result.rows[0];
        }
    }

    // Strategy 3: look up by phone hash alone
    if (phoneHash) {
        const result = await query(
            `SELECT * FROM identities
             WHERE tenant_id = $1 AND phone_hash = $2 AND deleted_at IS NULL
             LIMIT 1`,
            [tenantId, phoneHash]
        );
        if (result.rows.length > 0) {
            return result.rows[0];
        }
    }

    return null;
}

// ----------------------------------------------------------------------------
// getIdentityById
// ----------------------------------------------------------------------------
//
// Fetches an identity by its UUID, with tenant scoping enforced.
// Returns null if no identity exists with that ID for the given tenant.
//
// Tenant scoping prevents an attacker who somehow gets a valid UUID from
// reading data belonging to a different tenant.
// ----------------------------------------------------------------------------

async function getIdentityById(tenantId, identityId) {
    if (!tenantId) {
        throw new Error('tenantId is required');
    }
    if (!identityId) {
        throw new Error('identityId is required');
    }

    const result = await query(
        `SELECT * FROM identities
         WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL
         LIMIT 1`,
        [tenantId, identityId]
    );

    return result.rows[0] || null;
}

// ----------------------------------------------------------------------------
// createIdentity
// ----------------------------------------------------------------------------
//
// Creates a new identity record from already-hashed identifiers and
// sanitized display values.
//
// This is a low-level function. Most callers should use resolveIdentity()
// instead, which handles the find-or-create flow.
//
// The resolution_key is computed deterministically from the hashes so that
// future lookups using the same identifiers find this record.
// ----------------------------------------------------------------------------

async function createIdentity(tenantId, identityData) {
    if (!tenantId) {
        throw new Error('tenantId is required');
    }

    const {
        emailHash,
        phoneHash,
        displayEmail,
        displayPhone,
        displayName,
    } = identityData;

    if (!emailHash && !phoneHash) {
        throw new Error('At least one of emailHash or phoneHash is required');
    }

    const resolutionKey = generateResolutionKey(emailHash, phoneHash);

    const result = await query(
        `INSERT INTO identities (
            tenant_id,
            email_hash,
            phone_hash,
            resolution_key,
            display_email,
            display_phone,
            display_name,
            match_source
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'deterministic')
         RETURNING *`,
        [
            tenantId,
            emailHash || null,
            phoneHash || null,
            resolutionKey,
            displayEmail || null,
            displayPhone || null,
            displayName || null,
        ]
    );

    return result.rows[0];
}

// ----------------------------------------------------------------------------
// resolveIdentity
// ----------------------------------------------------------------------------
//
// The high-level "find or create" operation. Given raw PII, this function:
//   1. Hashes the inputs
//   2. Looks for an existing identity matching the hashes
//   3. Returns the existing identity if found
//   4. Creates a new identity if not found
//
// Returns an object: { identity, created }
//   identity: the identity record (existing or newly created)
//   created: true if a new identity was created, false if existing matched
//
// This is the primary function the HTTP layer will call.
//
// Note: identity merging (the case where email matches identity A and phone
// matches a different identity B) is not handled in this initial version.
// That logic will be added in a follow-on session. For now, if both an email
// and phone are provided and they match different identities, we return the
// email match (because email is checked first).
// ----------------------------------------------------------------------------

async function resolveIdentity(tenantId, identifiers, actor) {
    if (!tenantId) {
        throw new Error('tenantId is required');
    }

    const { email, phone, name } = identifiers || {};

    if (!email && !phone) {
        throw new Error('At least one of email or phone is required');
    }

    // For the identity_hashed audit row (Step 8): which PII fields the
    // caller provided. Names only - never values, never hashes.
    const fieldsProvided = [
        email ? 'email' : null,
        phone ? 'phone' : null,
        name ? 'name' : null,
    ].filter(Boolean);

    // Hash the identifiers
    const emailHash = email ? hashPII(email) : null;
    const phoneHash = phone ? hashPII(normalizePhone(phone)) : null;

    // Sanitize for display
    const displayEmail = email ? sanitizeEmail(email) : null;
    const displayPhone = phone ? sanitizePhone(phone) : null;

    try {
        return await withTransaction(async (client) => {
            // Try to find existing identity using the inputs.
            let existing = null;

            // Strategy 1: full match by resolution key
            if (emailHash && phoneHash) {
                const resolutionKey = generateResolutionKey(emailHash, phoneHash);
                const result = await client.query(
                    `SELECT * FROM identities
                     WHERE tenant_id = $1 AND resolution_key = $2 AND deleted_at IS NULL
                     LIMIT 1`,
                    [tenantId, resolutionKey]
                );
                if (result.rows.length > 0) existing = result.rows[0];
            }

            // Strategy 2: email hash
            if (!existing && emailHash) {
                const result = await client.query(
                    `SELECT * FROM identities
                     WHERE tenant_id = $1 AND email_hash = $2 AND deleted_at IS NULL
                     LIMIT 1`,
                    [tenantId, emailHash]
                );
                if (result.rows.length > 0) existing = result.rows[0];
            }

            // Strategy 3: phone hash
            if (!existing && phoneHash) {
                const result = await client.query(
                    `SELECT * FROM identities
                     WHERE tenant_id = $1 AND phone_hash = $2 AND deleted_at IS NULL
                     LIMIT 1`,
                    [tenantId, phoneHash]
                );
                if (result.rows.length > 0) existing = result.rows[0];
            }

            if (existing) {
                // Audit rides the transaction (Step 8, fail-closed): PII was
                // processed and an identity disclosed; if the audit insert
                // fails the whole operation rolls back.
                await writeAudit(client, auditIdentityHashed(actor, tenantId, existing.id, {
                    created: false,
                    fieldsProvided,
                }));
                return { identity: existing, created: false };
            }

            // No existing identity found - create one
            const resolutionKey = generateResolutionKey(emailHash, phoneHash);

            const result = await client.query(
                `INSERT INTO identities (
                    tenant_id,
                    email_hash,
                    phone_hash,
                    resolution_key,
                    display_email,
                    display_phone,
                    display_name,
                    match_source
                 )
                 VALUES ($1, $2, $3, $4, $5, $6, $7, 'deterministic')
                 RETURNING *`,
                [
                    tenantId,
                    emailHash,
                    phoneHash,
                    resolutionKey,
                    displayEmail,
                    displayPhone,
                    name || null,
                ]
            );

            await writeAudit(client, auditIdentityHashed(actor, tenantId, result.rows[0].id, {
                created: true,
                fieldsProvided,
            }));

            return { identity: result.rows[0], created: true };
        });
    } catch (err) {
        // Concurrent insert race: another transaction inserted the same identity
        // first, so our transaction aborted with a unique constraint violation.
        // The transaction is gone; we need a fresh query (which the pool provides)
        // to fetch what the other transaction created.
        if (err.code === '23505') {
            const resolutionKey = generateResolutionKey(emailHash, phoneHash);
            const fallback = await query(
                `SELECT * FROM identities
                 WHERE tenant_id = $1 AND resolution_key = $2 AND deleted_at IS NULL
                 LIMIT 1`,
                [tenantId, resolutionKey]
            );

            if (fallback.rows.length > 0) {
                // The original transaction is gone, so the audit row cannot
                // ride it; a single pool-level INSERT is atomic on its own.
                // Fail-closed still holds: if this write throws, the error
                // propagates and the identity is never disclosed.
                await writeAudit({ query }, auditIdentityHashed(
                    actor, tenantId, fallback.rows[0].id, {
                        created: false,
                        fieldsProvided,
                    }));
                return { identity: fallback.rows[0], created: false };
            }
        }

        // Any other error, re-raise
        throw err;
    }
}

// ----------------------------------------------------------------------------
// Exports
// ----------------------------------------------------------------------------

module.exports = {
    findIdentityByHash,
    getIdentityById,
    createIdentity,
    resolveIdentity,
};
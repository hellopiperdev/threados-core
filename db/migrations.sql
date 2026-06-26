-- ============================================================================
-- ThreadOS Core - Migrations
-- ============================================================================
--
-- This file accumulates schema changes added after the initial schema.sql.
-- Each migration is wrapped in checks so it can be safely re-applied.
--
-- Migrations are tracked in the schema_migrations table created in schema.sql.
-- ============================================================================


-- ============================================================================
-- Migration 002: Registered Verticals
-- ============================================================================
--
-- Tracks which vertical modules are registered with Core and where their
-- JWKS (JSON Web Key Set) endpoints are located. Core fetches public keys
-- from these endpoints to verify JWT signatures on incoming requests.
--
-- Bible references:
--   Decision 18: Service-to-service auth via signed JWT with verified tenant claims
--   Decision 7: Opinionated gatekeeper - only registered verticals can call Core
-- ============================================================================

CREATE TABLE IF NOT EXISTS registered_verticals (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Stable identifier used as JWT 'iss' claim (e.g., 'threados-auto')
    slug VARCHAR(100) UNIQUE NOT NULL,
    
    -- Human-readable name (only for ops/debugging)
    display_name VARCHAR(200) NOT NULL,
    
    -- Where to fetch this vertical's public keys (JWKS endpoint)
    -- In development, may point to a local file URL or a mock endpoint.
    -- In production, points to the vertical's actual /.well-known/jwks.json
    jwks_url TEXT NOT NULL,
    
    -- Cache TTL in seconds. After this many seconds, Core re-fetches the
    -- JWKS document. Default 1 hour balances freshness against load.
    jwks_cache_ttl_seconds INTEGER NOT NULL DEFAULT 3600,
    
    -- Lifecycle
    is_active BOOLEAN NOT NULL DEFAULT true,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Lookup index on slug (used at every JWT verification)
CREATE INDEX IF NOT EXISTS registered_verticals_slug_active
    ON registered_verticals (slug)
    WHERE is_active = true;

-- Trigger to auto-update updated_at on row changes
DROP TRIGGER IF EXISTS registered_verticals_update_timestamp ON registered_verticals;
CREATE TRIGGER registered_verticals_update_timestamp
    BEFORE UPDATE ON registered_verticals
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

COMMENT ON TABLE registered_verticals IS
    'Verticals registered with Core, each pointing to their JWKS endpoint. Bible Decision 18.';


-- Record this migration
INSERT INTO schema_migrations (version, description)
VALUES ('002_registered_verticals', 'Add registered_verticals table for JWT vertical registration')
ON CONFLICT (version) DO NOTHING;


-- ============================================================================
-- Migration 003: Event Capture Support
-- ============================================================================
--
-- Prepares the events table for the Step 6 event capture API.
--
--   - event_id: client-provided idempotency key. Bible Decision 8 distinguishes
--     client-supplied identifiers from Core-generated ones, so this is a
--     separate column from the Core-generated `id` primary key. Submitting the
--     same (tenant_id, event_id) twice is a no-op success.
--
--   - device_fingerprint: optional anonymous identifier. An event must carry at
--     least one of identity_id, session_id, or device_fingerprint. This is a
--     label captured with the event (Bible Decision 20: device context is for
--     aggregate analytics, NOT cross-session identification of anonymous users).
--
--   - session_id made nullable: the base schema declared it NOT NULL, but an
--     anonymous event may be keyed on device_fingerprint alone, so session_id
--     is no longer universally required.
--
-- Bible references:
--   Decision 8: Event schema structure (client vs Core-generated fields)
--   Decision 20: Cookieless-first; device context is a label, not a tracker
-- ============================================================================

ALTER TABLE events ADD COLUMN IF NOT EXISTS event_id UUID;
ALTER TABLE events ADD COLUMN IF NOT EXISTS device_fingerprint VARCHAR(200);
ALTER TABLE events ALTER COLUMN session_id DROP NOT NULL;

-- Idempotency: a given client event_id may be submitted at most once per tenant.
-- The partial predicate (WHERE event_id IS NOT NULL) leaves any legacy rows
-- without an event_id untouched while enforcing uniqueness for all new events.
CREATE UNIQUE INDEX IF NOT EXISTS events_tenant_event_id
    ON events (tenant_id, event_id)
    WHERE event_id IS NOT NULL;

INSERT INTO schema_migrations (version, description)
VALUES ('003_event_capture', 'Add event_id idempotency key + device_fingerprint, make session_id nullable for event capture')
ON CONFLICT (version) DO NOTHING;
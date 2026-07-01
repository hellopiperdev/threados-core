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


-- ============================================================================
-- Migration 004: session_id is an opaque external identifier
-- ============================================================================
--
-- The base schema typed session_id as UUID. That was wrong: a session_id is
-- minted by an external system (Express, Rails, frontend SDK session stores)
-- whose format Core does not own and therefore cannot dictate. Real-world
-- session IDs are opaque strings (e.g. "s%3AABC123.sig"), not UUIDs. Validation
-- now accepts them as opaque (src/lib/validation.js validateOptionalOpaqueId),
-- so the column must store them as text or every non-UUID session_id 500s on
-- insert.
--
-- We retype to VARCHAR(200) to mirror device_fingerprint, the other opaque
-- identifier on this table. The column is already nullable (migration 003), so
-- only the type changes; existing UUID values cast cleanly to text.
--
-- No constraint blocks this: session_id has no foreign key, and the dependent
-- index events_tenant_session (tenant_id, session_id, event_timestamp) is
-- rebuilt automatically by ALTER COLUMN TYPE.
--
-- Guarded so repeat runs (the runner re-executes this whole file) don't trigger
-- an unnecessary table rewrite once the column is already VARCHAR.
--
-- Bible references:
--   Decision 7:  Core constrains only what Core owns; opaque external IDs are
--                accepted as opaque, not forced into a Core-defined shape.
--   Decision 20: Cookieless-first; session_id is a label captured with the
--                event, not a Core-generated identity key.
-- ============================================================================

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'events'
          AND column_name = 'session_id'
          AND data_type = 'uuid'
    ) THEN
        ALTER TABLE events
            ALTER COLUMN session_id TYPE VARCHAR(200) USING session_id::text;
    END IF;
END $$;

INSERT INTO schema_migrations (version, description)
VALUES ('004_session_id_opaque', 'Retype events.session_id from UUID to VARCHAR(200): session_id is an opaque external identifier, not a Core-owned UUID')
ON CONFLICT (version) DO NOTHING;


-- ============================================================================
-- Migration 005: Consent data model (Step 7 Session 1)
-- ============================================================================
--
-- Replaces the placeholder consent_records table from migration 001 with the
-- settled Step 7 consent design. The placeholder was never written to by any
-- code path (no references in src/, tests/, or docs/; zero rows in dev) and
-- its shape predates the Step 7 design phase, so it is dropped outright rather
-- than altered.
--
-- The new model, per the Step 7 design decisions:
--
--   - Normalized relational tables with CHECK-constrained vocabulary columns,
--     not JSONB. Consent has a fixed dimensional structure
--     (purpose x vendor x channel x data_category x jurisdiction); auditability,
--     indexability, and type safety all demand real columns.
--
--   - Practical bitemporal, append-only history (consent_records):
--     effective_from / effective_until are VALID time (when the decision is in
--     force; NULL effective_until = currently in effect), recorded_at is SYSTEM
--     time (when Core learned of it). Consent changes are recorded by INSERTing
--     a superseding row, never by UPDATE. Append-only is an APPLICATION-LEVEL
--     convention (Session 2's write path is INSERT-only by construction), not a
--     DB trigger: the tenant/identity foreign keys must cascade deletions for
--     the right-to-erasure workflow (Bible Decision 6), and a row-level
--     UPDATE/DELETE-blocking trigger would break that cascade.
--
--   - current_consent projection: one row per dimension tuple holding what is
--     currently in effect, maintained synchronously in the same transaction as
--     consent_records inserts (Session 3). Write-time consent enforcement
--     (Session 4) reads this table with a single indexed lookup. No row here
--     (and no row in consent_records) means NO consent - the strictest,
--     framework-agnostic default.
--
--   - state records what the customer decided: granted / denied / withdrawn.
--     withdrawn is distinct from denied - denied means the customer never
--     agreed; withdrawn means a prior grant was revoked.
--
--   - consent_basis records the epistemic status of our knowledge of that
--     decision (the per-record half of Bible Decision 14; the tenant-level
--     half, tenants.compliance_posture, already exists). state and basis are
--     orthogonal: a record imported from a legacy CRM may be state=granted,
--     consent_basis=undocumented - we believe consent existed, we can't prove
--     it. Enforcement rules combining posture x basis x purpose live in Core
--     code (Session 4), not in schema constraints and not per-tenant.
--
--   - vendor is an opaque external identifier (same rule as events.session_id,
--     migration 004): Core does not own vendor naming, so it bounds length and
--     nothing else. jurisdiction is an ISO 3166-1 alpha-2 country code or
--     subdivision code ('US', 'US-CA'); the full valid-code list is too large
--     for a CHECK, so format validation happens at the application layer.
--
--   - capture_context and reason are vertical-provided free text stored
--     verbatim, length-bounded. Vertical-specific detail ("imported from
--     dealer's DMS during onboarding") lives there - Core doesn't know what a
--     DMS is; modules do. Emptiness and PII scanning are application-layer
--     concerns (Session 2), consistent with the events properties pipeline.
--
--   - All vocabulary CHECKs accept exact lowercase values only; case variants
--     are rejected, never coerced.
--
-- Bible references:
--   Decision 4:  Tenant-scoped - consent records FK to tenant-scoped identities
--   Decision 7:  Opinionated gatekeeper - controlled vocabularies enforced at
--                the schema; opaque external IDs bounded, not shaped
--   Decision 10: No raw PII - capture_context/reason are scanned at the
--                application layer before insert (Session 2)
--   Decision 13: Multi-dimensional consent - the five dimension columns
--   Decision 14: Compliance postures - consent_basis is the per-record basis
--   Decision 15: Write-time enforcement - current_consent is the fast lookup
-- ============================================================================

-- Step 1: drop the migration-001 placeholder. Guarded so this only ever
-- matches the legacy shape: only the placeholder has a `granted` boolean
-- column (the new design uses `state`), so re-runs and fresh builds (where
-- schema.sql already created the new shape) skip the drop.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'consent_records'
          AND column_name = 'granted'
    ) THEN
        DROP TABLE consent_records;
    END IF;
END $$;

-- Step 2: append-only consent history.
CREATE TABLE IF NOT EXISTS consent_records (
    record_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,

    -- Consent dimensions (Bible Decision 13). All NOT NULL: a record fully
    -- specifies every dimension; a decision spanning multiple channels or
    -- purposes is recorded as multiple rows (the batch POST supports this).
    purpose VARCHAR(30) NOT NULL
        CHECK (purpose IN ('marketing', 'personalization', 'analytics',
                           'service_operations', 'legal_compliance', 'fraud_prevention')),
    vendor VARCHAR(200) NOT NULL,
    channel VARCHAR(20) NOT NULL
        CHECK (channel IN ('email', 'sms', 'voice', 'push', 'mail', 'in_app')),
    data_category VARCHAR(20) NOT NULL
        CHECK (data_category IN ('behavioral', 'pii', 'location', 'financial', 'health')),
    jurisdiction VARCHAR(10) NOT NULL,

    -- What the customer decided
    state VARCHAR(20) NOT NULL
        CHECK (state IN ('granted', 'denied', 'withdrawn')),

    -- Epistemic status of our knowledge of that decision (Bible Decision 14)
    consent_basis VARCHAR(20) NOT NULL
        CHECK (consent_basis IN ('active_consent', 'documented_opt_in', 'legitimate_interest',
                                 'contract', 'legal_obligation', 'undocumented')),

    -- How the decision was captured
    captured_via VARCHAR(30) NOT NULL
        CHECK (captured_via IN ('web_form', 'email_response', 'phone', 'in_person',
                                'imported', 'api_direct', 'paper_form')),
    capture_context TEXT NOT NULL CHECK (length(capture_context) <= 2000),
    reason TEXT NOT NULL CHECK (length(reason) <= 2000),

    -- Practical bitemporal: valid time (effective_*) + system time (recorded_at)
    effective_from TIMESTAMP WITH TIME ZONE NOT NULL,
    effective_until TIMESTAMP WITH TIME ZONE,
    recorded_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CHECK (effective_until IS NULL OR effective_until > effective_from)
);

-- Temporal history reads: "show me this customer's consent history" and
-- point-in-time reconstruction both scan by (tenant, identity) ordered by
-- system time.
CREATE INDEX IF NOT EXISTS consent_records_tenant_identity_recorded
    ON consent_records (tenant_id, identity_id, recorded_at DESC);

COMMENT ON TABLE consent_records IS
    'Append-only bitemporal consent history. Never UPDATEd; supersession is a new INSERT. Bible Decisions 13, 14, 15.';

-- Step 3: current-consent projection for write-time enforcement.
-- The composite primary key IS the uniqueness guarantee (one current-state row
-- per dimension tuple) and, via its leading columns, the index for the
-- "what's this customer's full consent state?" lookup.
CREATE TABLE IF NOT EXISTS current_consent (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,

    purpose VARCHAR(30) NOT NULL
        CHECK (purpose IN ('marketing', 'personalization', 'analytics',
                           'service_operations', 'legal_compliance', 'fraud_prevention')),
    vendor VARCHAR(200) NOT NULL,
    channel VARCHAR(20) NOT NULL
        CHECK (channel IN ('email', 'sms', 'voice', 'push', 'mail', 'in_app')),
    data_category VARCHAR(20) NOT NULL
        CHECK (data_category IN ('behavioral', 'pii', 'location', 'financial', 'health')),
    jurisdiction VARCHAR(10) NOT NULL,

    state VARCHAR(20) NOT NULL
        CHECK (state IN ('granted', 'denied', 'withdrawn')),
    consent_basis VARCHAR(20) NOT NULL
        CHECK (consent_basis IN ('active_consent', 'documented_opt_in', 'legitimate_interest',
                                 'contract', 'legal_obligation', 'undocumented')),

    effective_from TIMESTAMP WITH TIME ZONE NOT NULL,

    -- The consent_records row that produced this current state. No cascade
    -- action: history rows are never deleted independently of their identity,
    -- and this FK makes a stray direct DELETE on consent_records fail loudly.
    source_record_id UUID NOT NULL REFERENCES consent_records(record_id),

    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- One current-state row per dimension tuple (Session 3 upserts against this)
    PRIMARY KEY (tenant_id, identity_id, purpose, vendor, channel, data_category, jurisdiction)
);

DROP TRIGGER IF EXISTS current_consent_update_timestamp ON current_consent;
CREATE TRIGGER current_consent_update_timestamp
    BEFORE UPDATE ON current_consent
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

COMMENT ON TABLE current_consent IS
    'Denormalized projection of currently-effective consent, one row per dimension tuple. Maintained in the same transaction as consent_records inserts. Bible Decision 15.';

INSERT INTO schema_migrations (version, description)
VALUES ('005_consent_data_model', 'Replace placeholder consent_records with bitemporal append-only consent history + current_consent projection (Step 7 Session 1)')
ON CONFLICT (version) DO NOTHING;

-- ============================================================================
-- Migration 006: Event types declare their implicated consent purpose
-- ============================================================================
--
-- Write-time consent enforcement (Step 7 Session 4, Bible Decision 15) needs
-- to know which consent purpose an event implicates. Purpose cannot be a
-- constant: Decision 14's Standard posture accepts legitimate interest "for
-- operational events" - so an order-status event implicates
-- service_operations while a page view implicates analytics, and only the
-- vertical knows which. Decision 13: "verticals declare which regulatory
-- regimes apply to their events" - the event type registry is where that
-- declaration lives.
--
-- The default is 'analytics' - the most consent-gated purpose an event can
-- implicate (it never passes without active consent / documented opt-in
-- under any posture) - so an event type that never declared a purpose fails
-- CLOSED, not open. Existing registry rows get the same conservative
-- default.
--
-- The vocabulary mirrors the consent purpose CHECK on consent_records.
-- Marketing/personalization are activation purposes, not capture purposes,
-- but the column accepts the full vocabulary: Core doesn't preempt a
-- vertical declaring an event type it genuinely captures for marketing - the
-- rule map simply demands active consent for it.
--
-- Bible references:
--   Decision 13: Multi-dimensional consent model (verticals declare regimes)
--   Decision 14: Tenant-level compliance postures
--   Decision 15: Write-time consent enforcement
-- ============================================================================

ALTER TABLE event_type_registry
    ADD COLUMN IF NOT EXISTS implicated_purpose VARCHAR(30) NOT NULL DEFAULT 'analytics'
    CONSTRAINT event_type_registry_implicated_purpose_check
    CHECK (implicated_purpose IN ('marketing', 'personalization', 'analytics',
                                  'service_operations', 'legal_compliance', 'fraud_prevention'));

INSERT INTO schema_migrations (version, description)
VALUES ('006_event_type_implicated_purpose', 'Add implicated_purpose to event_type_registry: event types declare the consent purpose they implicate for write-time enforcement (Step 7 Session 4)')
ON CONFLICT (version) DO NOTHING;


-- ============================================================================
-- Migration 007: current_consent carries the validity window's end
-- ============================================================================
--
-- Session 5 robustness exploration (HIGH-1): a grant whose effective_until
-- lapses by clock-tick stayed in the projection as 'granted' forever - the
-- projection had no effective_until column, so neither write-time enforcement
-- nor the read API could see the expiry, and no superseding write ever
-- arrives for a grant that simply runs out. Capture succeeded on lapsed
-- consent, and the stored snapshot asserted an authorization that had
-- expired - a Decision 15 violation.
--
-- Fix (Session 5 ruling): the projection stores effective_until, the upsert
-- writes it, and both readers (the enforcement lookup in src/lib/events.js
-- and getCurrentConsent in src/lib/consent.js) filter to rows whose window
-- covers now. An expired grant becomes invisible the moment its window
-- lapses: no row for the tuple means no consent - the invariant doing its
-- job. Lapsed rows may linger physically until the next write supersedes
-- them; the reader filters make them inert.
--
-- No CHECK constraint here (consent_records already enforces
-- effective_until > effective_from at the source; the projection is derived
-- data, and keeping both build paths' constraint sets identical matters
-- more than a redundant second check).
--
-- The backfill UPDATE is idempotent (IS DISTINCT FROM makes re-runs no-ops)
-- and copies the window end from each projection row's source record.
--
-- Bible references:
--   Decision 15: Write-time consent enforcement - the projection must not
--                assert consent whose validity window has ended.
-- ============================================================================

ALTER TABLE current_consent
    ADD COLUMN IF NOT EXISTS effective_until TIMESTAMP WITH TIME ZONE;

UPDATE current_consent
SET effective_until = cr.effective_until
FROM consent_records cr
WHERE cr.record_id = current_consent.source_record_id
  AND current_consent.effective_until IS DISTINCT FROM cr.effective_until;

INSERT INTO schema_migrations (version, description)
VALUES ('007_current_consent_effective_until', 'Add effective_until to current_consent so enforcement and reads can see expiry (Step 7 Session 5, finding HIGH-1)')
ON CONFLICT (version) DO NOTHING;

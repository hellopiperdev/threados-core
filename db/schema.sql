-- ============================================================================
-- ThreadOS Core Schema
-- ============================================================================
-- Version: 1.0
-- 
-- This schema implements the ThreadOS Core data model as defined in the
-- ThreadOS Bible. Each section is labeled with the Bible decision(s) it
-- implements for traceability.
--
-- This schema covers ThreadOS CORE ONLY. Vertical modules (Auto, Hospitality,
-- etc.) have their own schemas in their own repositories.
-- ============================================================================


-- ============================================================================
-- SECTION 1: Extensions and Setup
-- ============================================================================

-- For UUID generation (used everywhere as primary keys)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- For cryptographic functions (HMAC-SHA256 hashing)
CREATE EXTENSION IF NOT EXISTS "pgcrypto";


-- ============================================================================
-- SECTION 2: Helper Functions
-- Bible: Decision 1 (HMAC-SHA256), Decision 7 (Gatekeeper - sanitization)
-- ============================================================================

-- ----------------------------------------------------------------------------
-- hash_pii: Hash a piece of PII using HMAC-SHA256
-- 
-- In production, the salt will come from Google Secret Manager. For development
-- in Codespaces, we use a default salt. The same salt MUST be used consistently
-- or identity resolution will fail.
--
-- Note: This function exists in the database for reference and one-off queries.
-- The application code (Node.js) is the primary place hashing happens, because
-- the salt should not be visible in database logs.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION hash_pii(
    input_value TEXT,
    salt TEXT DEFAULT 'threados_dev_salt_replace_in_production'
) RETURNS VARCHAR(64) AS $$
BEGIN
    IF input_value IS NULL OR input_value = '' THEN
        RETURN NULL;
    END IF;
    
    -- HMAC-SHA256: keyed hash, returns 64-character hex string
    RETURN encode(
        hmac(lower(trim(input_value)), salt, 'sha256'),
        'hex'
    );
END;
$$ LANGUAGE plpgsql IMMUTABLE;

COMMENT ON FUNCTION hash_pii IS 
    'HMAC-SHA256 hash of PII for identity resolution. Bible Decision 1.';


-- ----------------------------------------------------------------------------
-- generate_resolution_key: Create a deterministic key from available hashes
-- 
-- Used to look up identities when we have multiple possible identifiers.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION generate_resolution_key(
    email_hash VARCHAR(64),
    phone_hash VARCHAR(64)
) RETURNS VARCHAR(128) AS $$
BEGIN
    RETURN encode(
        digest(
            COALESCE(email_hash, 'NONE') || '|' || COALESCE(phone_hash, 'NONE'),
            'sha256'
        ),
        'hex'
    );
END;
$$ LANGUAGE plpgsql IMMUTABLE;


-- ----------------------------------------------------------------------------
-- sanitize_email: Mask email for display (j***@example.com)
-- Bible: Architectural principle - we never display raw PII
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION sanitize_email(email TEXT) 
RETURNS VARCHAR(100) AS $$
DECLARE
    parts TEXT[];
    username TEXT;
    domain TEXT;
BEGIN
    IF email IS NULL OR email = '' THEN
        RETURN NULL;
    END IF;
    
    parts := string_to_array(email, '@');
    IF array_length(parts, 1) != 2 THEN
        RETURN '***@***.***';
    END IF;
    
    username := parts[1];
    domain := parts[2];
    
    IF length(username) > 1 THEN
        username := substr(username, 1, 1) || repeat('*', least(length(username) - 1, 5));
    END IF;
    
    RETURN username || '@' || domain;
END;
$$ LANGUAGE plpgsql IMMUTABLE;


-- ----------------------------------------------------------------------------
-- sanitize_phone: Mask phone for display (***-***-1234)
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION sanitize_phone(phone TEXT) 
RETURNS VARCHAR(20) AS $$
DECLARE
    digits TEXT;
BEGIN
    IF phone IS NULL THEN
        RETURN NULL;
    END IF;
    
    -- Strip non-digits
    digits := regexp_replace(phone, '[^0-9]', '', 'g');
    
    IF length(digits) < 10 THEN
        RETURN NULL;
    END IF;
    
    RETURN '***-***-' || right(digits, 4);
END;
$$ LANGUAGE plpgsql IMMUTABLE;


-- ----------------------------------------------------------------------------
-- update_updated_at: Trigger function to auto-update updated_at columns
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;


-- ============================================================================
-- SECTION 3: Tenants
-- Bible: Decision 4 (tenant-scoped), Decision 5 (abstract Core)
-- ============================================================================

-- ----------------------------------------------------------------------------
-- tenants: The fundamental boundary of data isolation in Core
--
-- Core knows nothing about what a "tenant" represents in the real world
-- (dealership, hotel, casino, enterprise customer). That mapping is the
-- vertical module's responsibility. Core only knows: tenants are isolated,
-- their data does not cross-contaminate.
-- ----------------------------------------------------------------------------
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Human-readable identifier for ops/debugging (NOT shown to end users)
    slug VARCHAR(100) UNIQUE NOT NULL,
    
    -- Display name (only visible to the vertical that owns this tenant)
    display_name VARCHAR(200) NOT NULL,
    
    -- Which vertical module owns this tenant (informational; Core doesn't act on this)
    vertical_module VARCHAR(50) NOT NULL,
    
    -- Lifecycle status
    status VARCHAR(20) NOT NULL DEFAULT 'active' 
        CHECK (status IN ('active', 'suspended', 'archived')),
    
    -- Compliance posture (Bible Decision 14)
    compliance_posture VARCHAR(20) NOT NULL DEFAULT 'strict'
        CHECK (compliance_posture IN ('strict', 'standard', 'legacy')),
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER tenants_update_timestamp
    BEFORE UPDATE ON tenants
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

COMMENT ON TABLE tenants IS 
    'Abstract tenant concept. Core knows nothing about what a tenant represents. Bible Decision 5.';


-- ============================================================================
-- SECTION 4: Identities
-- Bible: Decision 1 (hashing), Decision 2 (deterministic + AI hooks),
--        Decision 4 (tenant-scoped), Decision 5 (abstract Core)
-- ============================================================================

-- ----------------------------------------------------------------------------
-- identities: Tenant-scoped hashed customer identities
--
-- A single real-world person can exist as multiple identities in Core if they
-- interact with multiple tenants. This is intentional - consent given to
-- Tenant A doesn't transfer to Tenant B.
--
-- Layer 2 hooks (Bible Decision 2): confidence_score, match_reason, match_source
-- are populated for future AI-powered probabilistic matching. For MVP they
-- remain NULL or use deterministic defaults.
-- ----------------------------------------------------------------------------
CREATE TABLE identities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    
    -- Hashed identifiers (no raw PII ever)
    email_hash VARCHAR(64),
    phone_hash VARCHAR(64),
    
    -- Resolution key for fast lookups
    resolution_key VARCHAR(128) NOT NULL,
    
    -- Sanitized display values (j***@example.com format)
    display_email VARCHAR(100),
    display_phone VARCHAR(20),
    display_name VARCHAR(100),
    
    -- Layer 2 hooks for future AI-powered identity matching (Bible Decision 2)
    -- confidence_score: 0.00 to 1.00; NULL for deterministic matches
    confidence_score DECIMAL(3,2),
    -- match_source: how this identity was matched/created
    match_source VARCHAR(30) NOT NULL DEFAULT 'deterministic'
        CHECK (match_source IN ('deterministic', 'ai_probabilistic', 'manual', 'imported')),
    -- match_reason: JSON metadata about why a match was made
    match_reason JSONB,
    
    -- Identity merging support
    merged_into_id UUID REFERENCES identities(id),
    merged_at TIMESTAMP WITH TIME ZONE,
    
    -- Lifecycle
    is_active BOOLEAN NOT NULL DEFAULT true,
    deleted_at TIMESTAMP WITH TIME ZONE,  -- For tombstoning (Bible Decision 16)
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    -- A tenant can't have two identities with the same email_hash (deterministic uniqueness)
    UNIQUE (tenant_id, email_hash),
    UNIQUE (tenant_id, phone_hash),
    UNIQUE (tenant_id, resolution_key)
);

-- Indexes for fast lookups (Bible: identity resolution at write time)
CREATE INDEX identities_tenant_email ON identities (tenant_id, email_hash) 
    WHERE email_hash IS NOT NULL AND deleted_at IS NULL;
CREATE INDEX identities_tenant_phone ON identities (tenant_id, phone_hash) 
    WHERE phone_hash IS NOT NULL AND deleted_at IS NULL;
CREATE INDEX identities_resolution_key ON identities (tenant_id, resolution_key)
    WHERE deleted_at IS NULL;
CREATE INDEX identities_merged_into ON identities (merged_into_id) 
    WHERE merged_into_id IS NOT NULL;

CREATE TRIGGER identities_update_timestamp
    BEFORE UPDATE ON identities
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

COMMENT ON TABLE identities IS 
    'Tenant-scoped hashed customer identities. Bible Decisions 1, 2, 4.';


-- ============================================================================
-- SECTION 5: Consent
-- Bible: Decision 13 (multi-dimensional), Decision 14 (compliance postures),
--        Decision 15 (write-time enforcement)
-- ============================================================================

-- ----------------------------------------------------------------------------
-- consent_records: Multi-dimensional consent tracking
--
-- Each row captures consent for a specific (identity, purpose) combination
-- with full audit metadata.
-- ----------------------------------------------------------------------------
CREATE TABLE consent_records (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    
    -- Multi-dimensional consent attributes (Bible Decision 13)
    purpose VARCHAR(100) NOT NULL,
    vendor VARCHAR(100),  -- NULL means "any vendor"
    channel VARCHAR(50),  -- email, sms, phone, mail, push, web, etc. NULL means "any"
    data_category VARCHAR(50) NOT NULL DEFAULT 'standard',
    jurisdiction VARCHAR(20),  -- 'gdpr', 'ccpa', 'tcpa', etc.
    
    -- The consent itself
    granted BOOLEAN NOT NULL,
    
    -- How consent was captured (Bible: legal defensibility)
    consent_basis VARCHAR(50) NOT NULL DEFAULT 'active_consent'
        CHECK (consent_basis IN (
            'active_consent',           -- User explicitly consented
            'legitimate_interest',      -- Legal basis for operational use
            'contractual_necessity',    -- Required to fulfill contract
            'legal_obligation',         -- Required by law
            'undocumented',             -- Legacy data; needs re-verification
            'withdrawn'                 -- Previously granted, now revoked
        )),
    
    -- Capture audit trail (Bible Decision 13)
    captured_via VARCHAR(50) NOT NULL,  -- 'web_form', 'phone_call', 'import', etc.
    capture_context JSONB,  -- IP, user agent, form name, etc. (with no raw PII)
    
    -- IAB TCF compliance fields (when applicable)
    tcf_version VARCHAR(10),
    tcf_string TEXT,
    
    -- Lifecycle
    valid_from TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    valid_until TIMESTAMP WITH TIME ZONE,
    superseded_by UUID REFERENCES consent_records(id),
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX consent_identity ON consent_records (identity_id, valid_from DESC);
CREATE INDEX consent_tenant_identity_purpose 
    ON consent_records (tenant_id, identity_id, purpose);

CREATE TRIGGER consent_records_update_timestamp
    BEFORE UPDATE ON consent_records
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

COMMENT ON TABLE consent_records IS 
    'Multi-dimensional consent tracking with audit trail. Bible Decisions 13, 14, 15.';


-- ============================================================================
-- SECTION 6: Events
-- Bible: Decision 8 (event schema), Decision 9 (additive evolution),
--        Decision 10 (no PII in properties), Decision 15 (consent snapshot)
-- ============================================================================

-- ----------------------------------------------------------------------------
-- event_type_registry: Registered event types with their property schemas
-- Bible Decision 8: Strict event name + field-level validation
--
-- Verticals must register event types before they can send events.
-- This is what catches "page_viewed" vs "pageViewed" typos and "Y" vs true.
-- ----------------------------------------------------------------------------
CREATE TABLE event_type_registry (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    
    event_name VARCHAR(100) NOT NULL,
    event_category VARCHAR(50) NOT NULL,
    
    -- JSON Schema defining valid properties for this event type
    properties_schema JSONB NOT NULL DEFAULT '{}',
    
    -- Lifecycle
    is_active BOOLEAN NOT NULL DEFAULT true,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE (tenant_id, event_name)
);

CREATE TRIGGER event_type_registry_update_timestamp
    BEFORE UPDATE ON event_type_registry
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();


-- ----------------------------------------------------------------------------
-- events: The normalized event stream
--
-- Anonymous events (identity_id IS NULL) are held for 30 days for retroactive
-- identification (Bible Decision 21). After 30 days they're deleted; the
-- aggregate counters in event_aggregates (built later) preserve the analytics.
-- ----------------------------------------------------------------------------
CREATE TABLE events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    
    -- Identity (NULL for anonymous events; populated retroactively if user identifies)
    identity_id UUID REFERENCES identities(id) ON DELETE SET NULL,
    
    -- Session and source (Bible Decision 20: cookieless, server-managed)
    session_id UUID NOT NULL,
    source_type VARCHAR(50) NOT NULL,  -- 'web', 'mobile', 'server', 'import', etc.
    source_id VARCHAR(100),
    
    -- Event identification (Bible Decision 8)
    event_name VARCHAR(100) NOT NULL,
    event_category VARCHAR(50) NOT NULL,
    
    -- Flexible properties (validated against event_type_registry)
    properties JSONB NOT NULL DEFAULT '{}',
    
    -- Consent snapshot at moment of capture (Bible Decision 15)
    consent_snapshot JSONB NOT NULL,
    
    -- Timing
    event_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    received_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    processed_at TIMESTAMP WITH TIME ZONE,
    
    -- Validation status
    validation_status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (validation_status IN ('pending', 'valid', 'invalid', 'rejected')),
    validation_errors JSONB,
    
    -- Retention status for anonymous holding pattern
    retention_status VARCHAR(30) NOT NULL DEFAULT 'standard'
        CHECK (retention_status IN ('standard', 'pending_identification', 'expired'))
);

CREATE INDEX events_tenant_identity_time 
    ON events (tenant_id, identity_id, event_timestamp DESC) 
    WHERE identity_id IS NOT NULL;

CREATE INDEX events_tenant_session 
    ON events (tenant_id, session_id, event_timestamp);

CREATE INDEX events_pending_identification 
    ON events (tenant_id, received_at) 
    WHERE retention_status = 'pending_identification';

COMMENT ON TABLE events IS 
    'Normalized event stream. Bible Decisions 8, 9, 10, 15, 20, 21.';


-- ============================================================================
-- SECTION 7: Customers
-- Bible: Decision 11 (loyalty as a lens) - customer context for verticals
-- ============================================================================

-- ----------------------------------------------------------------------------
-- customers: Unified customer profile derived from identity + events + loyalty
--
-- This is a denormalized projection updated by background processes. It's the
-- "lens" that verticals query to show "Loyal Customer Level 5, John Peters."
-- ----------------------------------------------------------------------------
CREATE TABLE customers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    identity_id UUID NOT NULL UNIQUE REFERENCES identities(id) ON DELETE CASCADE,
    
    -- Computed segmentation and tier
    lifecycle_stage VARCHAR(50),  -- 'prospect', 'active', 'at_risk', 'churned', etc.
    tier VARCHAR(50),             -- 'bronze', 'silver', 'gold', 'platinum' or custom
    trajectory VARCHAR(20),       -- 'rising', 'stable', 'declining'
    
    -- Engagement metrics
    first_seen_at TIMESTAMP WITH TIME ZONE,
    last_seen_at TIMESTAMP WITH TIME ZONE,
    total_events INTEGER DEFAULT 0,
    
    -- Custom tags and segments (flexible)
    tags JSONB DEFAULT '[]',
    
    -- Computed scores (populated by background processes)
    engagement_score DECIMAL(5,2),
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX customers_tenant_tier ON customers (tenant_id, tier);
CREATE INDEX customers_tenant_lifecycle ON customers (tenant_id, lifecycle_stage);

CREATE TRIGGER customers_update_timestamp
    BEFORE UPDATE ON customers
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();


-- ============================================================================
-- SECTION 8: Loyalty
-- Bible: Decision 11 (lens + ledger), Decision 12 (phased signing)
-- ============================================================================

-- ----------------------------------------------------------------------------
-- loyalty_transactions: The ledger of points earned and redeemed
-- ----------------------------------------------------------------------------
CREATE TABLE loyalty_transactions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    
    -- Transaction details
    transaction_type VARCHAR(30) NOT NULL
        CHECK (transaction_type IN ('earn', 'redeem', 'expire', 'adjust', 'transfer')),
    points INTEGER NOT NULL,  -- Can be negative for redemptions/expirations
    
    -- Why this transaction happened
    reason VARCHAR(100) NOT NULL,
    reference_id VARCHAR(200),  -- e.g., 'service_appointment_abc123'
    
    -- Optional vertical context (Core doesn't interpret this)
    context JSONB,
    
    -- Future signing hooks (Bible Decision 12)
    -- These remain NULL until we implement signed snapshots in a later phase
    signature TEXT,
    key_id VARCHAR(50),
    
    -- Timing
    occurred_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX loyalty_transactions_identity 
    ON loyalty_transactions (tenant_id, identity_id, occurred_at DESC);


-- ----------------------------------------------------------------------------
-- loyalty_balances: Materialized current balance per identity
--
-- Updated as transactions are added. Reading current balance is a single
-- row lookup instead of a sum across millions of transactions.
-- ----------------------------------------------------------------------------
CREATE TABLE loyalty_balances (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    
    current_points INTEGER NOT NULL DEFAULT 0,
    lifetime_earned INTEGER NOT NULL DEFAULT 0,
    lifetime_redeemed INTEGER NOT NULL DEFAULT 0,
    
    -- Timestamps
    last_transaction_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    PRIMARY KEY (tenant_id, identity_id)
);

CREATE TRIGGER loyalty_balances_update_timestamp
    BEFORE UPDATE ON loyalty_balances
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();


-- ============================================================================
-- SECTION 9: Integrations
-- Bible: Original handoff doc - integration framework
-- ============================================================================

-- ----------------------------------------------------------------------------
-- integrations: Configuration for third-party connector integrations
--
-- Verticals own the actual integration logic. This table just tracks
-- which integrations are configured for which tenants, and stores
-- encrypted credentials.
-- ----------------------------------------------------------------------------
CREATE TABLE integrations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    
    -- What this integration is
    integration_type VARCHAR(50) NOT NULL,  -- 'fortellis', 'cdk', 'hubspot', etc.
    display_name VARCHAR(200) NOT NULL,
    
    -- Encrypted credentials (encrypted at application layer, not in DB)
    -- We store the encrypted blob; the application has the decryption key
    credentials_encrypted TEXT,
    
    -- Configuration that doesn't need encryption
    config JSONB DEFAULT '{}',
    
    -- Lifecycle
    is_active BOOLEAN NOT NULL DEFAULT true,
    last_sync_at TIMESTAMP WITH TIME ZONE,
    last_sync_status VARCHAR(20),
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX integrations_tenant ON integrations (tenant_id, is_active);

CREATE TRIGGER integrations_update_timestamp
    BEFORE UPDATE ON integrations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();


-- ============================================================================
-- SECTION 10: Schema Migration Tracking
-- ============================================================================

-- ----------------------------------------------------------------------------
-- schema_migrations: Track which migrations have been applied
--
-- Allows us to safely re-run the migration script without re-applying
-- changes that are already in place.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS schema_migrations (
    version VARCHAR(50) PRIMARY KEY,
    description TEXT NOT NULL,
    applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO schema_migrations (version, description) 
VALUES ('001_initial_core_schema', 'Initial ThreadOS Core schema: tenants, identities, consent, events, customers, loyalty, integrations')
ON CONFLICT (version) DO NOTHING;


-- ============================================================================
-- SECTION 11: Permissions and Roles
-- Bible: Architectural principle - defense in depth
-- ============================================================================

-- We use the default postgres user for development. Production will create
-- specific service accounts via Secret Manager and IAM.

-- Document the intended role structure for future production setup:
COMMENT ON SCHEMA public IS 
    'ThreadOS Core schema. Production will use: core_service (full access), audit_service (read-only). Bible Decision 18.';


-- ============================================================================
-- End of Schema
-- ============================================================================
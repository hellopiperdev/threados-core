# The ThreadOS Bible

**The foundational reference document for ThreadOS.**

This document is the single source of truth for ThreadOS — its vision, architecture, decisions, reasoning, and roadmap. It is the primary reference for anyone working on the platform, including future engineers, partners, and the authors themselves when revisiting decisions months or years later.

**Document maintenance:** This document is a living reference. When decisions change or new foundational decisions are made, this document must be updated. A decision log section at the end tracks changes.

**Last updated:** April 2026
**Version:** 1.0

---

## Table of Contents

1. [Project Vision](#1-project-vision)
2. [The ThreadOS Thesis](#2-the-threados-thesis)
3. [Architecture Overview](#3-architecture-overview)
4. [Technology Stack](#4-technology-stack)
5. [ThreadOS Core — Complete Component Definition](#5-threados-core--complete-component-definition)
6. [ThreadOS Auto — First Vertical Module](#6-threados-auto--first-vertical-module)
7. [Foundational Decisions (With Reasoning)](#7-foundational-decisions-with-reasoning)
8. [Architectural Principles](#8-architectural-principles)
9. [Roadmap and Phasing](#9-roadmap-and-phasing)
10. [Strategic Ideas for Future Phases](#10-strategic-ideas-for-future-phases)
11. [Deferred Decisions](#11-deferred-decisions)
12. [Security and Compliance Posture](#12-security-and-compliance-posture)
13. [Development Philosophy](#13-development-philosophy)
14. [Glossary](#14-glossary)
15. [Decision Log](#15-decision-log)

---

## 1. Project Vision

**ThreadOS is a privacy-first growth operating system with a modular architecture.**

It is not a CRM. It is not a CDP. It is not an analytics platform. It is the **trust layer** that sits beneath those tools — the infrastructure that makes privacy, identity, consent, and loyalty work correctly across any vertical market.

### The Problem Being Solved

The marketing and customer-data industry is broken in specific, identifiable ways:

- **Data is scattered** across tools (CRMs, ERPs, DMSs, data lakes) that don't talk to each other cleanly. Integration layers between these tools are built by humans writing fragile scripts that break in stupid ways — the "flapjack country code" problem where one system accepts garbage data and that garbage becomes another system's problem.

- **Data is unused.** Organizations collect vast amounts of customer information and do almost nothing with it. Sales teams are committed to selling, not to maintaining CRMs. The data pile grows while the insights stagnate.

- **Data insight requires human follow-through that never happens.** Current tools (HubSpot lead scores, auto CRM prospect lists) provide scores or flags, but acting on them requires humans to build static workflows based on subjective thresholds. Those workflows become stale, drift from reality, and require ongoing maintenance that busy teams can't provide.

- **Privacy compliance is an afterthought.** Most platforms treat consent as a checkbox to tick rather than an architectural concern. When regulation shifts (GDPR, CCPA, state-by-state US laws), these platforms scramble. ThreadOS is built so that compliance is the default behavior, not an add-on.

- **Vertical-specific platforms don't share infrastructure.** Salesforce has Automotive Cloud. Cendyn has hospitality. None of these share customer trust infrastructure across verticals, so buyers reinvent identity, consent, and loyalty every time they adopt a new tool.

### ThreadOS's Answer

A modular platform where:

- **Core** is vertical-agnostic and owns identity, consent, events, and loyalty as universal infrastructure
- **Vertical modules** (Auto, Hospitality, Enterprise, Retail) plug into Core and handle domain-specific integrations and features
- **Privacy and compliance** are architectural defaults, not afterthoughts
- **AI augmentation** removes the human-workflow dependency that causes current tools to fail

### The Original Handoff Context

This document evolved from an original technical handoff that defined the three-phase MVP roadmap for ThreadOS Auto (Dealer Intelligence Hub, Loyalty Engine, Command Console) and the Core components (Identity Graph, Consent Management, Signals Engine, Data Hub, Loyalty Wallet). Those definitions remain valid and are captured in detail below, but have been enriched by the architectural decisions documented in this Bible.

### Validated Market Signal

ThreadOS Intent (https://intent.threados.io/demo/) is a live technology demo that validates the market appetite for runtime verification as a product category. The Cookieless Readiness Scanner (https://scanner.threados.io/) reinforces this — the market wants tools that verify what actually happens vs. what's configured, especially as the tracking industry transitions away from cookies.

---

## 2. The ThreadOS Thesis

### Core Differentiators

**1. The Trust Layer**
ThreadOS Core is not a feature set — it is the place where trust is defined once, correctly, for the entire platform. Consent logic, identity handling, runtime verification, and auditability live in Core. Verticals consume and benefit from these properties without having to implement them separately.

**2. Runtime Verification**
ThreadOS measures what actually happens, not what was assumed or configured. When a client claims "500 leads captured this month," Core can independently verify that 500 consented, validated events actually fired. This is a verifiable truth layer that most competitors can't offer because their data model wasn't designed for it.

**3. Cross-Vertical Architecture**
Core is deliberately agnostic to verticals. Adding new verticals (Healthcare, Fitness, Real Estate) is a matter of writing a new module — not reinventing trust infrastructure. Competitors who built vertical-first cannot cleanly extract this capability.

**4. AI-Augmented Decisioning (Planned)**
ThreadOS replaces the "human builds a workflow" pattern with AI that reads customer context and produces specific, actionable recommendations. This is planned for MVP 3 but informs decisions made now.

**5. Incentive Alignment**
The architecture rewards clients who do their job well (earn identification through value) and makes it impossible for clients to rely on surveillance. Good marketers get the most from ThreadOS. Bad marketers self-select out.

### Strategic Moats

- **Defensibility through trust infrastructure:** Features live in verticals. Defensibility lives in Core. Ripping out Core leaves a commodity product.
- **Vertical addition economics:** Each new vertical becomes cheaper to add because Core's trust properties are already built. Competitors pay full cost per vertical.
- **Data quality that improves as the world gets more private:** Cookie-based competitors watch their data degrade. ThreadOS's identified-user architecture strengthens.
- **Compliance as a selling feature:** "We help you turn your legacy customer database into a compliant, consent-backed asset" is a differentiated offering that competitors avoid.

### Philosophy Summary

> "We can't sell transparency if we aren't transparent. We can't sell privacy if we aren't bulletproof on security. The cost of doing this right isn't overhead — it is the product."

---

## 3. Architecture Overview

### The Hybrid Model

ThreadOS uses a hybrid architecture:

- **Shared PostgreSQL database** serves as the single source of truth
- **Core exposes internal APIs** for identity, consent, events, and loyalty
- **Each vertical module has its own Node.js backend** in separate repositories
- **Modules call Core APIs** for all data operations involving identity or PII
- **Verticals can evolve independently** without refactoring Core

### The Two-Layer Model

**Core Layer (vertical-agnostic):**
- Knows nothing about dealerships, hotels, casinos, or any vertical-specific concepts
- Owns: Identity, Consent, Events, Loyalty, Audit
- Provides canonical APIs that any vertical can call
- Enforces universal rules (PII hashing, consent, validation)

**Vertical Layer (domain-specific):**
- Auto, Hospitality, Enterprise, Retail modules
- Owns: Domain-specific data models (dealerships, vehicles, hotels, rooms, products)
- Handles integrations with third-party systems (Fortellis, DMS, CRM, PMS)
- Translates messy real-world data into Core's clean canonical format
- Builds vertical-specific UI and workflows

### Data Flow Pattern

**Inbound (the common case):**
```
Source Systems (VinSolutions, CDK via Fortellis, etc.)
    ↓
Vertical Module (ThreadOS Auto)
    — reads raw data
    — translates to Core canonical format
    — validates internally
    ↓
ThreadOS Core
    — validates again (defense in depth)
    — enforces consent, hashing, schema
    — stores
```

**Outbound (the planned pattern):**
```
ThreadOS Core
    — produces intelligence (segments, scores, recommendations)
    ↓
Vertical Module
    — receives Core's output
    — distributes to third-party systems (HubSpot, CRM, DMS)
    ↓
Source Systems
    — act on intelligence in the tools humans already use
```

This bidirectional pattern is critical: verticals are not just ETL pipelines into Core. They are also distribution channels for Core's intelligence back into the tools businesses actually use.

---

## 4. Technology Stack

### Confirmed Stack

- **Frontend:** React (dashboards and user interfaces)
- **Backend:** Node.js (API layer, event handling)
- **Data Processing:** Python (ML, analytics, complex business logic)
- **Database:** PostgreSQL 15+
- **Cloud Platform:** Google Cloud Platform (GCP)

### Why This Stack

- Production-ready and enterprise-grade
- Complete ownership and control
- Native security and compliance capabilities
- Scales from MVP to production without rewrites
- Professional, shippable applications

### GCP Services Used

**Primary:**
- **Cloud SQL (PostgreSQL):** Application database, separate audit database
- **Cloud Run:** Deployment target for Core and vertical modules
- **Secret Manager:** Keys, salts, credentials
- **Cloud Logging:** Operational/system logs
- **Pub/Sub:** Async messaging for audit pipeline and background work
- **IAM:** Service-to-service authentication
- **Cloud Armor + Load Balancer:** DDoS protection, WAF, public ingress

**Future/Planned:**
- **BigQuery:** Analytical store for business events and aggregate analytics
- **Vertex AI:** LLM integration for MVP 3 conversational features
- **Cloud Tasks:** Background job orchestration

### Development Environment

- **GitHub Codespaces:** Primary development environment
- **PostgreSQL 15 in container:** Local/Codespaces database
- **GitHub Actions:** CI/CD pipeline

---

## 5. ThreadOS Core — Complete Component Definition

### 5.1 Identity Graph & PII Hashing

**Purpose:** Hash and encode all PII before any module can access it. Protect clients from themselves — auto dealerships are historically bad at security; Core makes data protection the default.

**Implementation:**
- PostgreSQL tables for hashed identities
- Node.js API endpoints for hash/unhash operations
- HMAC-SHA256 hashing with key stored in Secret Manager (production) or env vars (dev)
- Deterministic hashing for consistent identity resolution within a tenant
- Support for future AI-powered probabilistic matching (Layer 2)

**Key Schema Hooks for Future:**
- Confidence score fields
- Match reason metadata
- Match source (deterministic / AI / manual)

### 5.2 Consent Management

**Purpose:** IAB TCF compliant consent with a unified preference center. Make compliance the default, not an add-on.

**Implementation:**
- Multi-dimensional consent records (purposes, vendors, channels, data categories, jurisdictions)
- Write-time enforcement on all events
- Tenant-level compliance postures (Strict / Standard / Legacy)
- Consent basis declared per record at import
- Consent snapshot captured on every event
- Anonymous event holding pattern (30 days)
- Full audit trail with supersession history

### 5.3 Signals Engine

**Purpose:** Real-time data quality checks, duplicate detection, cohort creation. The gatekeeper layer that prevents bad data from entering the system.

**Implementation:**
- Event validation pipeline with strict schema enforcement
- Event name registry (verticals register before sending)
- Field-level schema validation (catches value sprawl like "Y" vs true)
- Duplicate detection algorithms
- Segment builder for safe audience activation
- Actionable error messages when validation fails

### 5.4 ThreadOS Data Hub

**Purpose:** Normalize data from multiple sources (Shopify, GA4, HubSpot, DMS, CRM). Provides a connector framework verticals can build against.

**Implementation:**
- Connector framework for each integration type
- Normalized schema: customers, events, offers
- Read-only to start, write capabilities added later
- Validation and translation happens in verticals before reaching Core

### 5.5 Tokenized Loyalty Wallet

**Purpose:** Verifiable loyalty infrastructure that works across all verticals. Core provides the ledger and context; verticals handle domain-specific marketing.

**Implementation:**
- Token issuance, tracking, and redemption
- Balance queries
- Tier/segment computation (the "lens" layer)
- Configurable tier definitions per tenant
- Schema designed for future signed snapshots
- Key rotation supported from day one
- Future: cross-vertical loyalty with explicit consent (B2C play)

### 5.6 Audit Infrastructure

**Purpose:** Forensics, compliance, and regulatory-grade record-keeping. Separate from application database for isolation and security.

**Implementation:**
- Separate Cloud SQL instance for audit data
- Async pipeline via Pub/Sub (fire-and-forget from app perspective)
- Four log categories: Security, Data Mutation, Operations, Business Events
- Tiered retention: 90 days ops / 2 years security / 7 years mutations / 7 years business
- PII-safe logging (references identity_id, never raw PII)
- Tombstoning pattern preserves audit chain through deletions

---

## 6. ThreadOS Auto — First Vertical Module

Three MVPs as defined in the original handoff document. These remain valid targets; the underlying Core architecture now supports them more robustly.

### 6.1 MVP 1: Dealer Intelligence Hub (8–10 weeks)

**Goal:** Real-time dashboard connecting ad click → site event → lead form → appointment → visit → sale

**Core Features:**
- Event capture layer (all touchpoints tracked)
- Journey recorder API (reconstruct customer paths)
- CRM/DMS read connector (import dealership data)
- Rule-based attribution engine (connect marketing to sales)
- Live funnel dashboard (React visualization)

**Technical Requirements:**
- Consume sanitized data from Core
- DMS integration (read-only initially)
- Real-time event streaming
- Attribution logic (first-touch, last-touch, multi-touch)

**Success Metrics:**
- Dealership sees complete customer journey
- Attribution matches sales data within 10%
- Dashboard loads under 2 seconds
- 90%+ event capture rate (no data loss)

### 6.2 MVP 2: ThreadOS Loyalty Engine (+8 weeks after MVP 1)

**Goal:** Membership and engagement layer connecting sales, service, and marketing

**Core Features:**
- Customer identity graph (Core-powered)
- Intent listener (detect service needs, trade-in signals)
- Engagement triggers (automated outreach)
- Rewards framework (tokenized loyalty from Core)
- Retention dashboard (churn prediction)

**Technical Requirements:**
- Use Core's loyalty wallet infrastructure
- Predictive churn models (Python)
- Automated engagement workflows

**Success Metrics:**
- Measurable churn reduction
- Engagement triggers fire within 5 minutes
- Loyalty token adoption rate above 50%
- Service appointment bookings increase

### 6.3 MVP 3: ThreadOS Command Console (+8–12 weeks after MVP 2)

**Goal:** Transform dealership data into actionable AI intelligence

**Core Features:**
- Conversational AI layer (LLM-driven insights)
- Predictive attribution engine (ML-based forecasting)
- Alert system (anomaly detection)
- Dealer Brain Panel (executive dashboard)

**Technical Requirements:**
- LLM integration (Vertex AI / Claude / GPT-4)
- Forecasting models (Python)
- Natural language interface for dealers
- Push-back integration into third-party tools (HubSpot, CRM)

**Success Metrics:**
- AI predictions accurate within 20% margin
- Dealers use Command Console daily
- Alert system reduces lost opportunities
- Forecast accuracy improves over time

---

## 7. Foundational Decisions (With Reasoning)

Each decision below captures not only what was decided but why, including tradeoffs considered and alternatives rejected. This is the most important section of the document for long-term reference.

### Decision 1: HMAC-SHA256 for PII Hashing

**Decision:** Use HMAC-SHA256 with a secret key stored in Google Secret Manager (production) or environment variables (development) for all PII hashing operations.

**Reasoning:**
Password hashing algorithms (bcrypt, Argon2) were considered but rejected because they produce non-deterministic outputs — the same email hashed twice produces different results. This breaks identity resolution, which requires deterministic matching to recognize returning customers.

Plain SHA-256 with salt was considered but HMAC-SHA256 is the textbook-correct construction for keyed hashing. It handles edge cases (length-extension attacks, salt concatenation subtleties) that DIY salt-concat approaches miss. Performance and cost are identical.

**Tradeoffs accepted:**
- If the database and the HMAC key are both compromised, an attacker could brute-force common emails. Mitigation: key lives in Secret Manager, separate from the database.

**Cost:** Negligible. Secret Manager is fetched once at app startup and cached in memory. No per-operation cost.

### Decision 2: Deterministic Identity Resolution (with Layer 2 AI roadmap)

**Decision:** MVP uses deterministic matching only — two records are the same identity only when they share a hashed identifier (email_hash or phone_hash). Schema is designed to support future AI-powered probabilistic matching as Layer 2.

**Reasoning:**
Three approaches were considered:
- **Strict matching** (no merging) rejected as naive — creates duplicate records unnecessarily
- **Probabilistic matching** (ML-based guessing from behavior, IP, device) rejected for MVP — privacy-risky, inaccurate, moves away from where regulation is headed
- **Deterministic matching** selected — industry standard for privacy-first CDPs, explainable to auditors, fits "privacy first" principle

AI-powered matching (Layer 2) is valuable and will be built later. It solves a different problem: the genuinely ambiguous cases that deterministic matching can't resolve (similar names, different emails, same timing patterns). This is a strategic differentiator — most competitors drop these cases on a human's desk via CRM queues. ThreadOS will resolve them with AI and confidence scores.

**Schema hooks built in now:**
- Confidence score field
- Match reason metadata
- Match source (deterministic / AI / manual)

### Decision 3: Synchronous Merging at Write Time

**Decision:** Identity merges happen synchronously during event capture, not via background jobs.

**Reasoning:**
Background job approach was considered for faster writes, but rejected because verticals need to act on identified customer data immediately. Waiting for a background job to run means ThreadOS Auto can't show the service advisor the customer's full context until the job completes.

**Tradeoffs accepted:**
- Slightly slower writes (negligible at current scale)
- Simpler code, no background job infrastructure needed for this path
- Can migrate to async later if volume demands

### Decision 4: Tenant-Scoped Identity

**Decision:** Identity resolution happens within a tenant, not across tenants. The same email used by two different tenants creates two separate Core identities.

**Reasoning:**
This was the result of an important question: if Jane is a customer of Friendly Ford (Auto) and Sunset Hotels (Hospitality), are they the same Core identity?

**Position considered:** Yes — the whole point of shared Core is that Jane is Jane across verticals. This was rejected because Jane didn't consent to Sunset Hotels knowing about her Friendly Ford activity. GDPR and CCPA require consent to be specific to a data controller.

**Position adopted:** Identities are tenant-scoped. Jane at Friendly Ford and Jane at Sunset Hotels are two separate Core identity records. This matches legal reality.

**Future flexibility:** Cross-vertical identity/loyalty as explicit opt-in feature with separate consent (the B2C play). Built on top later, not assumed by default.

### Decision 5: Abstract Core — Core Knows Nothing About Verticals

**Decision:** Core uses a fully abstract `tenant_id` concept. Core has no knowledge of dealerships, hotels, casinos, dealer groups, or any vertical-specific customer structure.

**Reasoning:**
Initial draft of the schema had "organization_id" in Core, which encoded a dealer-group-shaped concept. This was caught and corrected. The moment Core knows what an "organization" is, Core has opinions about verticals, which breaks the abstraction that makes Core's cross-vertical value possible.

**What this enables:**
- New verticals added by building new modules, not by refactoring Core
- Salesforce-style vertical-entanglement is avoided
- Each vertical maps its internal customer structure to abstract tenant_ids as it sees fit

### Decision 6: GDPR Deletion Scoped Per Vertical

**Decision:** A deletion request received by one vertical deletes only that vertical's tenant's data in Core. Other verticals using the same person as a customer are untouched.

**Reasoning:**
Follows from Decision 4 (tenant-scoped identity). If Jane is two separate Core identities (one for Friendly Ford, one for Sunset Hotels), a deletion request at Friendly Ford deletes the Friendly Ford identity and leaves the Sunset Hotels identity intact. This is how GDPR actually works — each data controller handles deletion independently.

**Protection against cross-contamination:** Because identities aren't merged across tenants in the first place, there's no risk of accidentally leaking the existence of another tenant's relationship with the same person.

### Decision 7: Opinionated Gatekeeper Principle

**Decision:** Core accepts input from verticals, validates strictly, and rejects bad input with errors specific enough that the vertical can fix the problem at its source.

**Reasoning:**
The "flapjack country code" problem — one system accepts garbage data and that garbage becomes every downstream system's problem — is a major cause of data quality decay. ThreadOS cannot claim to be the trust layer while accepting garbage.

**Applies to:**
- PII (Core refuses raw PII in event properties, requires hashing)
- Event validation (schema, types, registered event names)
- Canonical formats (ISO country codes, E.164 phones, boolean vs. "Y"/"yes"/"yeah")
- Consent (events without valid consent for their purpose are rejected)

**Error design:** Errors must tell the vertical exactly what was wrong and what the vertical needs to fix. No silent drops, no cryptic failures. Verticals handle the translation from messy reality to canonical format; Core enforces the canonical format strictly.

### Decision 8: Event Schema Structure

**Decision:** Canonical required/optional fields plus a flexible `properties` JSON blob with guardrails. Event names and their property schemas must be registered at the vertical layer before events can be sent.

**Required fields:**
- `tenant_id`, `event_name`, `event_category`, `event_timestamp`, `source_type`, `consent_snapshot`

**Optional fields:**
- `identity_id`, `session_id`, `device_id`, `source_id`

**Core-generated fields:**
- `id`, `received_at`, `processed_at`, `validation_status`

**Flexible:**
- `properties` JSON with size limits, no PII allowed, reserved key namespace, type validation per registered schema

**Reasoning:**
Strict event name registry catches typos (`page_viewed` vs `pageViewed`). Field-level schema validation catches value sprawl (`"Y"` vs `true`). The combination prevents most of the common data quality failures seen in analytics platforms.

Source systems (VinSolutions, Fortellis, etc.) do not know ThreadOS exists. Verticals are responsible for translating source system chaos into Core-canonical events. Core enforces the canonical format as a pure boundary.

### Decision 9: Additive-Only Schema Evolution

**Decision:** Event schemas evolve by adding new fields, not by versioning. Old fields can be deprecated but not removed. No v1/v2/v3.

**Reasoning:**
Versioned schemas require maintaining translation layers between versions, which is operationally painful. Additive-only evolution works for the vast majority of real-world schema changes and keeps the system simpler indefinitely.

### Decision 10: No PII in Event Properties

**Decision:** Core scans event `properties` for PII patterns (email regex, phone regex) and rejects events containing raw PII. Verticals must hash PII through the identity API before including anything identifying in an event.

**Reasoning:**
Without this rule, verticals could bypass Core's hashing by stuffing `{"email": "jane@example.com"}` into properties. The gatekeeper principle demands that PII has exactly one path into Core — through the identity hashing API.

### Decision 11: Loyalty as a Lens, Not Just a Ledger

**Decision:** Core's loyalty system provides both the transactional ledger (points in, points out, balances, expirations) AND the context/tier computation that turns raw activity into actionable customer identity at the moment of interaction.

**Reasoning:**
This decision came from recognizing what "loyalty" really needs to do in ThreadOS. The killer use case isn't processing points — it's transforming "randomdude@email.com" into "Loyal Customer Level 5 John Peters, 12 visits YTD, trending up, last serviced 4 months ago."

**Core's loyalty responsibilities:**
- The ledger (transactions, balances)
- Tier/segment computation (configurable per tenant)
- Signed snapshots for verification (later phase, schema ready now)
- Cross-context identity matching (already enabled by identity decisions)

**What Core does NOT do:**
- Marketing campaigns (vertical's job)
- Vertical-specific redemption logic
- Customer-facing app
- Point-of-interaction UX

### Decision 12: Phased Loyalty Token Signing

**Decision:** MVP stores loyalty tokens as plain database records. Signed snapshots for verification use cases come in a later phase. Schema includes nullable `signature` and `key_id` fields from day one.

**Reasoning:**
Blockchain was considered and rejected — wrong tool, enormous complexity, regulatory ambiguity, and the "blockchain loyalty" pattern has a track record of failure.

Signing every token at issuance was considered but rejected for MVP. Signed balance snapshots on demand (when verification is needed) covers the relevant use cases — proof of relationship history for ownership changes, regulatory audits, customer disputes.

**Schema hooks:** `signature` and `key_id` fields exist from day one. Signing logic is added in later phases without schema migration.

### Decision 13: Multi-Dimensional Consent Model

**Decision:** Consent records capture multiple dimensions: purposes, vendors, channels, data categories, jurisdictions. Core provides flexible structure; verticals declare which regulatory regimes apply to their events.

**Reasoning:**
Consent is multidimensional in regulatory reality. IAB TCF 2.2 defines 11 purposes; different jurisdictions have different rules; sensitive data categories have higher legal bars; different channels (email, SMS, phone) often have independent consent requirements.

**Core stays vertical-agnostic:** HIPAA logic doesn't live in Core. But Core's consent structure is flexible enough that a future Healthcare vertical can declare "these events require HIPAA-compliant consent" and Core enforces the rule.

### Decision 14: Tenant-Level Compliance Postures

**Decision:** Each tenant declares a compliance posture at onboarding: Strict, Standard, or Legacy.

- **Strict:** Every event requires documented, active consent. Rejects ambiguous.
- **Standard:** Legitimate interest accepted for operational events; active consent required for marketing.
- **Legacy:** Limited-use mode for imported data with undocumented consent; strict enforcement for new data.

Records imported into a tenant have a declared `consent_basis` (active consent / legitimate interest / undocumented / etc.) that determines how they can be used.

**Reasoning:**
The "do the right thing" impulse runs into market reality: dealerships have 50,000 records with 3 clean consent records and 49,997 in legal gray zones. A purist approach rejects 49,997 and loses the customer. A permissive approach betrays ThreadOS's core principle.

Compliance postures thread the needle: ThreadOS remains an opinionated gatekeeper, but the rules enforced depend on the tenant's declared posture and each record's declared consent basis. Strict enforcement still applies to new data regardless of posture. Legacy data is handled in a limited-use mode, can be used for defensible operational purposes, but requires active consent for marketing.

**Future feature:** Consent re-verification workflow — ThreadOS helps clients run campaigns to turn undocumented-consent records into documented consent. Adds compliance value as a sellable service.

**Liability shift:** Because tenants declare the consent basis, they own the declaration. ThreadOS enforces rules based on declarations. This appropriately shifts legal responsibility.

### Decision 15: Write-Time Consent Enforcement + Holding Patterns

**Decision:** Every event is checked against consent before storage. Events without valid consent for their purpose are rejected at write time. Anonymous (pre-identification) events are held for 30 days and retroactively associated if identification and consent arrive within that window.

**Reasoning:**
Query-time filtering was considered but rejected. Storing data you can't use creates compliance risk and data footprint. Write-time enforcement means "we don't have what we shouldn't have" — a stronger legal position and forces verticals to build consent-awareness into their pipelines from day one.

**30-day holding window:** Chosen as a balance between capturing pre-identification activity (which has legitimate attribution value) and not keeping anonymous data indefinitely. 30 days is used consistently across ThreadOS as the standard holding/grace period.

### Decision 16: Audit Logging on Separate Infrastructure

**Decision:** Audit data lives on a separate Cloud SQL instance from application data. Writes go through an async Pub/Sub pipeline so audit operations are never in the critical path for application responses.

**Storage architecture:**
- **Application DB (Cloud SQL):** Primary app data
- **Audit DB (separate Cloud SQL instance):** Append-only, separate credentials, separate failure domain
- **Cloud Logging:** Operational/system logs
- **Pub/Sub:** Async pipeline app → audit DB
- **BigQuery:** Future analytical store for business events

**Reasoning:**
Without separation, a deletion attack (automated "right to be forgotten" requests) could DoS the application because every deletion triggers extensive audit writes to the same database the app is trying to serve from. Separation also improves failure isolation (audit outage doesn't take down the app), reduces resource contention, and improves security (compromising the app shouldn't give access to manipulate audit logs).

**Protections built in:**
- Rate limiting at API layer (per IP, per tenant, per endpoint)
- Identity verification for sensitive operations
- Async processing for expensive operations (deletions, bulk imports)
- Anomaly detection on request patterns

**Retention:**
- Operational logs: 90 days
- Security events: 2 years
- Data mutations: 7 years
- Business events: 7 years

**PII in logs:** Logs reference identity_id only, never raw PII. Tombstoning pattern preserves the audit chain when identities are deleted.

### Decision 17: Critical Path vs Background Path Architectural Principle

**Decision:** Operations that write heavily or take significant time are separated from the real-time API response path.

**Critical path:** API responses to real-time user/system interactions. Must be lean, fast, and protected.

**Background path:** Audit writes, analytics, bulk operations, integration syncs, AI inference, large imports. Queued, separated, can be throttled.

**Reasoning:**
This emerged from the audit architecture discussion but applies broadly. Bulk imports, Fortellis syncs, AI model runs, analytics jobs — all have the same pattern: they could overwhelm shared infrastructure if run synchronously on the main path.

**Implementation principle:** These paths share data but not resources.

### Decision 18: GCP IAM for Service-to-Service Authentication

**Decision:** Core and vertical modules authenticate to each other using GCP IAM service accounts. Tenant context within each call is verified via a signed JWT claim.

**Two-layer approach:**
- **Layer 1 (Service-to-service via GCP IAM):** Answers "Is this really ThreadOS Auto calling?"
- **Layer 2 (Tenant context via signed JWT):** Answers "Which tenant is this operation for?"

**Reasoning:**
Static API keys considered — rejected because key leak = compromise, rotation is painful. mTLS considered — rejected as overkill for our scale. Plain JWTs considered — usable but GCP IAM is better because Google manages credential rotation automatically.

**Defense in depth:** If a service account is compromised, the attacker still needs to forge tenant JWT claims. Tenant_id becomes a cryptographically verified claim rather than a trusted input, eliminating the "wrong tenant" class of bugs.

**Development mode:** Shared secret via environment variables for Codespaces. Clearly marked as dev-only; production requires GCP IAM.

**Project structure:** Same GCP project, different service accounts per module. Simpler to operate, sufficient isolation, cheaper to run.

### Decision 19: Security Stack — All-In on GCP Native Primitives

**Decision:** Use GCP native services for security primitives: IAM for auth, Secret Manager for secrets, Cloud Armor + Load Balancer for ingress, Cloud Logging for operational logs, private VPC for network isolation.

**Reasoning:**
Alternative architectures (cloud-agnostic with Vault, Datadog, etc.) considered. Rejected because they increase the number of auth systems, credential surfaces, and integration points. More places for things to leak.

Going all-in on GCP reduces attack surface and leverages Google's security engineering at scale. Coupling to GCP's security infrastructure is leverage, not risk. The cost (~$100-300/month baseline) is insurance that would be multiples more expensive to replicate.

**Stack built from day one:**
- Private VPC
- Cloud Armor + Load Balancer for public ingress
- Secret Manager for all keys/secrets
- Cloud Logging with audit separation
- Code scanning for credentials in CI/CD
- Least-privilege IAM roles

### Decision 20: Cookieless-First Session and Device Identification

**Decision:** No persistent client-side device_id. Session IDs are server-managed and in-memory. Anonymous sessions stay anonymous unless identification happens within the session. Cross-device linking only for authenticated users.

**Identifier hierarchy:**
- **session_id:** In-memory, server-managed, 30-minute inactivity timeout
- **identity_id:** Populated at explicit identification events (form submission, login)
- **device_context:** Captured with events for aggregate analytics (browser family, mobile vs desktop, country) but NOT used for cross-session identification of anonymous users

**Reasoning:**
Traditional "device ID in a cookie or localStorage" is fundamentally a surveillance pattern — identifying users across sessions without requiring identification. ThreadOS's value proposition is the opposite of surveillance. Also, browsers are actively eroding the storage mechanisms that make persistent device tracking work.

The industry is moving cookieless. ThreadOS's own Cookieless Readiness Scanner validates this market direction. Building Core around persistent browser-side identification would contradict the brand.

**What we lose:** Individual-level anonymous cross-session tracking.
**What we gain:** Genuinely cookieless architecture; no dependency on browser storage behaviors; alignment with where regulation is heading; simpler architecture.

**Cross-device for identified users:** When Jane identifies on her phone and later on her laptop, Core matches them via email hash. This is opt-in, transparent cross-device tracking — not surveillance.

### Decision 21: Dual-Track Anonymous Event Handling

**Decision:** Every event is stored in two places simultaneously:
1. **Individual event record** — with session_id, held 30 days, deleted if no identification occurs, migrated to identified if it does
2. **Aggregate counter** — updated immediately, no individual identification, permanent retention

**Reasoning:**
Three approaches considered:
- Discard anonymous events entirely (rejected — throws away legitimate aggregate value)
- Store anonymously forever (rejected — privacy and compliance exposure)
- Dual-track (selected — correctly models the two legitimate uses)

The dual-track model delivers real-time analytics on anonymous traffic (aggregate) while supporting retroactive identification (individual, 30-day holding) without creating persistent individual records of unidentified users.

**Aggregate privacy protection:** Minimum cohort thresholds (5-10 events minimum per cell) prevent small-cell re-identification.

**Deletion handling:** Aggregate data is not subject to individual deletion requests because mathematically the individual's contribution is indistinguishable from the aggregate. Individual events are deleted on request or at the 30-day mark.

### Decision 22: Customer vs Client Tension — Explicit Resolution In Favor of Customer

**Decision:** When customer interests (privacy, transparency, control) and client interests (conversion data, attribution, marketing effectiveness) conflict, ThreadOS resolves architecturally in favor of the customer. Client value is delivered through higher-quality identified-user data and aggregate insights, not through surveillance of anonymous users.

**Reasoning:**
This tension exists in every customer data platform. Most platforms resolve it quietly in favor of the client. ThreadOS's architectural choice (cookieless, consent-enforced, identity-gated) makes the opposite choice explicit.

**What ThreadOS tells clients:**
1. We identify your customers the moment they identify themselves, better than anyone else
2. We give you rich context on identified customers in real time
3. We make your anonymous traffic useful at the aggregate level
4. We don't lie about what we have
5. We give you durable data ownership that improves as the world gets more private

**Incentive alignment:** Clients who earn identification through value benefit most. Clients who want surveillance self-select out.

---

## 8. Architectural Principles

Recurring principles that emerged from the foundational decisions. These guide future decisions even in areas not yet explicitly addressed.

### The Trust Layer Principle
Core is not a feature set. Core is where trust, truth, and identity are defined once, correctly, for the entire platform. Everything that makes ThreadOS defensible lives in Core.

### The Vertical Agnosticism Principle
Core knows nothing about dealerships, hotels, casinos, or any domain-specific concepts. The moment Core encodes vertical assumptions, it stops being cross-vertical. Verticals own their domain; Core owns universal properties.

### The Gatekeeper Principle
Core validates strictly and rejects bad input with actionable errors. Verticals are responsible for translating messy reality into canonical formats; Core enforces the canonical formats.

### The Privacy-First Principle
When customer privacy and client convenience conflict, privacy wins. Architecture rewards clients who earn consent through value and makes surveillance patterns impossible.

### The Runtime Truth Principle
Measure what actually happens, not what was configured or assumed. This applies to events, consent, attribution, loyalty — everything.

### The Critical Path vs Background Path Principle
Operations that write heavily or take significant time are isolated from the real-time API response path. Critical path is lean and fast; background path is queued and throttled.

### The Defense in Depth Principle
Never rely on a single protection. Tenant IDs are columns AND signed claims AND enforced by Row Level Security. Authentication is IAM AND JWT. Validation happens at the vertical AND at Core.

### The Incentive Alignment Principle
The architecture rewards the right behaviors. Clients who build identified relationships benefit most. Clients who want surveillance won't be happy — by design.

### The Bidirectional Intelligence Principle
Verticals are not just ETL pipelines into Core. They are also distribution channels for Core's intelligence back into third-party tools where humans actually work.

### The Transparent Honesty Principle
We don't claim data we don't have. Confidence scores reflect actual confidence. Aggregate is called aggregate. Probabilistic is called probabilistic.

---

## 9. Roadmap and Phasing

### Phase 1: Foundation (Weeks 1–4)

**Core:**
- Database schemas (Core + Auto)
- PII hashing API with HMAC-SHA256
- PostgreSQL with proper roles/permissions
- Consent management foundation
- Event capture API

**Auto:**
- Dealership data models
- DMS integration approach
- Event schema for auto vertical
- Attribution logic requirements

### Phase 2: MVP 1 Build (Weeks 5–10)

**Core:**
- Event capture API complete
- Journey recorder infrastructure
- Data sanitization pipeline
- Audit logging pipeline

**Auto:**
- Funnel dashboard UI (React)
- Attribution engine implementation
- DMS read connector (Fortellis)
- Journey visualization component

### Phase 3: MVP 2 Build (Weeks 11–18)

**Core:**
- Loyalty wallet infrastructure
- Token issuance system
- Rewards framework API
- Intent detection framework

**Auto:**
- Service reminder triggers
- Trade-in intent detection
- Retention dashboard UI
- Engagement automation workflows

### Phase 4: MVP 3 Build (Weeks 19–30)

**Core:**
- AI/LLM infrastructure
- Predictive models framework
- Anomaly detection system
- Forecasting pipeline
- Layer 2 probabilistic identity matching

**Auto:**
- Conversational AI for dealers
- Predictive attribution algorithms
- Dealer Brain Panel UI
- Alert system integration

### Phase 5: Second Vertical (post-MVP 3)

- ThreadOS Hospitality module
- Cross-vertical loyalty (B2C opt-in feature)
- Core improvements based on multi-vertical learning

---

## 10. Strategic Ideas for Future Phases

Ideas that emerged during foundational decisions that are worth preserving but are out of scope for MVP. These inform future product strategy.

### Product Strategy

- **Cross-vertical B2C loyalty app** — white-label preferred over direct-to-consumer; consumer-facing app where users earn across all their favorite ThreadOS-connected brands
- **Radical transparency in loyalty** — most loyalty programs are deliberately opaque because opacity helps businesses; ThreadOS takes the opposite position, making loyalty honest about what's earned and what's needed to earn more
- **Customer-facing audit/consent transparency UX** — end users can see exactly what data is held about them, what consent they've given, and what aggregate statistics they've contributed to
- **Cookieless Readiness Scanner as brand expression** — the existing tool at scanner.threados.io embodies ThreadOS's values

### Technical Capabilities

- **AI-driven decisioning as a Core capability** — not per-vertical; synthesizes identity + events + loyalty into specific actionable recommendations, eliminates the "human builds a workflow" dependency
- **Push-back integration into third-party tools** — Core's intelligence flows back through verticals into HubSpot, CRMs, DMSs so recommendations appear where humans already work
- **Signed loyalty snapshots** — cryptographic proof of relationship history for ownership changes, regulatory audits, customer disputes
- **Layer 2 AI-powered identity matching** — resolves ambiguous cases that deterministic matching can't; differentiator against HubSpot-style human-managed merge queues
- **BigQuery analytical layer** — business events pipeline for reporting and AI training data
- **DoS-resistant architecture as selling point** — dealerships have been targeted by fake lead spam; "ThreadOS is hardened against abuse" is a real market position

### Business Model

- **Compliance posture as onboarding pathway** — Legacy mode as entry point; tenants graduate toward Strict over time with ThreadOS's help
- **Consent re-verification as a sellable feature** — helps clients turn dirty databases into compliant, consent-backed assets; nobody else does this
- **Audit logs as customer-facing product feature** — enable clients to prove compliance to their own customers and regulators
- **ThreadOS architecture incentivizes high-quality marketing practice** — platform self-selects for good clients, which becomes a brand signal

### Market Positioning Lines

- "Data quality that improves as the world gets more private"
- "We make loyalty honest"
- "Stop relying on data that's disappearing. Start building a durable, consented, identified customer relationship."
- "Other platforms claim compliance. ThreadOS proves it."

---

## 11. Deferred Decisions

Decisions known to be needed but intentionally deferred. These will be addressed when building the relevant components.

- **End-user authentication for dashboards** — how dealership users log into ThreadOS Auto dashboards. Likely Firebase Auth or Auth0. Deferred to when dashboard UI is built.

- **Data export and portability formats** — GDPR requires data portability in machine-readable formats. Deferred to when customer-facing features are built.

- **Backup and disaster recovery specifics** — backup frequency, geographic redundancy, RTO/RPO targets. Operational decisions for deployment phase.

- **Exact Cloud SQL tier and scaling strategy** — depends on initial load characteristics. Deferred to deployment.

- **Specific ML/AI model choices for MVP 3** — Vertex AI vs Claude API vs GPT-4 selection depends on MVP 3 use cases.

- **Specific DMS integration order** — CDK, Reynolds, Dealertrack, VinSolutions, AutoManager. Prioritize based on first customer needs.

- **Pricing model** — per-tenant, per-event, hybrid. Business decision, not architectural.

---

## 12. Security and Compliance Posture

### Compliance Frameworks Targeted

- **GDPR** — EU general data protection
- **CCPA/CPRA** — California consumer privacy
- **IAB TCF 2.2** — advertising industry consent framework
- **TCPA** — US telephone consumer protection (particularly relevant for Auto)
- **FTC Safeguards Rule** — financial info during car purchases (Auto-specific)
- **SOC 2 Type II** — operational security controls (target for enterprise sales)

### Compliance Not Yet Targeted (Future)

- **HIPAA** — if Healthcare vertical is built
- **GLBA** — if deeper financial services capabilities are built
- **PCI-DSS** — if payment processing is built (currently avoided)
- **State-specific US laws** — growing patchwork; handled via jurisdiction dimension in consent

### Key Security Properties

- All PII hashed with HMAC-SHA256 before storage
- Database encrypted at rest (Cloud SQL default)
- All connections TLS-encrypted
- Row Level Security enforces tenant isolation
- Separate audit infrastructure prevents operational interference
- Least-privilege IAM roles per service
- No long-lived credentials in code
- Code scanning for credential leaks in CI/CD
- DoS protection at ingress (Cloud Armor)
- Audit trail for all mutations and access

### Incident Response (Future)

Incident response runbook, regular security audits, and penetration testing should be in place before enterprise customer deployment. Deferred to pre-launch operational phase.

---

## 13. Development Philosophy

### Build Principles

- **Privacy first** — every decision protects user privacy
- **Runtime truth** — measure what actually happens, not assumptions
- **Composable** — each piece works independently
- **Non-disruptive** — layer on top of existing systems
- **Production-grade** — build to ship, not just prototype

### Code Quality Standards

- Write tests alongside features, not after
- Document complex business logic
- Use descriptive variable names
- Handle errors explicitly
- Log important operations with structured logs
- Version all APIs (additive-only evolution)
- TypeScript for type safety where applicable

### Collaboration Approach

- Start with schema and API contracts
- Build Core foundation first
- Add vertical features incrementally
- Test integration points early
- Deploy frequently
- Update this Bible when decisions change

### Anti-Patterns Explicitly Avoided

- Storing raw PII anywhere except via Core's hashing API
- Building attribution logic that bypasses Core's consent checks
- Hard-coding credentials in code
- Skipping database migrations (always versioned)
- Ignoring error handling in integrations
- Building monolithic services (keep Core and verticals separated)
- Premature optimization
- Blockchain for anything (wrong tool for every problem we have)
- Probabilistic device fingerprinting of anonymous users
- Customer-facing opacity in loyalty or consent

---

## 14. Glossary

**Aggregate data** — Statistical information that cannot be traced back to an individual (e.g., "47 users viewed page X"). Not subject to individual deletion requests.

**Anonymous event** — An event captured before identification. Held for 30 days; retroactively associated if identification occurs, deleted otherwise.

**Audit trail** — Permanent record of significant operations (security events, data mutations, business events) stored on separate infrastructure.

**Client** — A business using ThreadOS (a dealership, hotel, enterprise customer). Not to be confused with "customer."

**Compliance posture** — A tenant's declared consent enforcement level (Strict / Standard / Legacy) that determines how records are handled.

**Consent basis** — The legal justification for holding or using a specific data record (active consent / legitimate interest / undocumented / etc.).

**Consent snapshot** — The state of a user's consent captured at the moment of an event, stored with the event for audit purposes.

**Core (ThreadOS Core)** — The vertical-agnostic trust layer of ThreadOS, handling identity, consent, events, loyalty, and audit.

**Customer** — An end person whose data is processed by ThreadOS (e.g., a dealership's car buyer). Not to be confused with "client."

**Deterministic matching** — Identity resolution based on exact matching of hashed identifiers (email_hash, phone_hash).

**Device context** — Aggregate category information about a device (browser family, mobile vs desktop) captured for analytics without cross-session identification.

**Device ID** — Deliberately NOT used in ThreadOS for cross-session tracking of anonymous users. Persistent client-side device identification is excluded by design.

**Event** — A record of something that happened (page view, form submit, purchase, etc.) with canonical fields defined by Core.

**Event name registry** — The list of permitted event names registered by verticals; catches typos and prevents sprawl.

**Field-level schema** — Per-event type definition of allowed fields, types, and values in the `properties` blob; catches value sprawl.

**Gatekeeper principle** — Core's role of strictly validating input and rejecting bad data with actionable errors.

**HMAC-SHA256** — The cryptographic function used for PII hashing, using a secret key stored in Secret Manager.

**Identity ID** — Core's internal UUID for a person, tenant-scoped, derived from hashed identifiers.

**Layer 2 (AI matching)** — Future AI-powered probabilistic identity matching that handles cases deterministic matching cannot.

**Probabilistic matching** — Identity resolution based on similarity signals (similar names, timing, patterns) rather than exact matches. Planned as Layer 2; not in MVP.

**Resolution key** — Deterministic key combining available hashed identifiers, used for identity lookups.

**Runtime verification** — ThreadOS's capability to independently verify that claimed events, consent, and identities actually exist. Central to the brand.

**Session ID** — In-memory, server-managed identifier for a continuous user interaction (~30 min inactivity timeout).

**Tenant** — An abstract concept in Core representing one customer of a vertical module. Core knows nothing about what a tenant actually is.

**Tombstoning** — Preserving an identity record with a "deleted" marker rather than physically deleting it, to maintain audit chain integrity through right-to-be-forgotten requests.

**Trust layer** — The architectural role Core plays — the place where trust properties are defined once for the entire platform.

**Vertical (ThreadOS Vertical)** — A domain-specific module built on top of Core (Auto, Hospitality, Enterprise, Retail).

---

## 15. Decision Log

This log tracks changes to foundational decisions over time. When a decision documented above is changed, a new entry is added here with the date, what changed, and why.

### Entry 1: Initial Decision Set — December 2024

All 22 foundational decisions in this document were made in the initial strategic foundation conversation. See individual decision sections for full reasoning.

### Template for Future Entries

```
### Entry N: [Short Title] — [Date]

**Decision(s) affected:** [Reference decision numbers/names]

**What changed:** [Before → After]

**Why:** [Reason for change]

**Impact:** [What needs to be updated in code, docs, or architecture]
```

---

## Document Maintenance Instructions

This document must be kept current. When any of the following happens, update this document:

1. A foundational decision is changed or extended
2. A new foundational decision is made
3. A deferred decision is resolved
4. A strategic idea is promoted to roadmap
5. An architectural principle is refined or added

Update the "Last updated" date at the top of the document and add an entry to the Decision Log when updating.

When in doubt, err on the side of documenting. The cost of over-documentation is small. The cost of lost context on a principled decision is large.

---

*End of ThreadOS Bible v1.0*

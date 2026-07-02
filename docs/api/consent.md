# Consent API

ThreadOS Core's consent API is the write and read surface for the consent model: verticals call it to record customer consent decisions and to read an identity's current consent state and history. Consent lives in Core as **append-only bitemporal truth** — every decision is a permanent history record carrying both when it was in force (valid time) and when Core learned of it (system time), and the "current state" is a projection maintained from that history, never a value edited in place. Regulatory frameworks (GDPR, CCPA, TCF 2.2) are interpretation layers over this model, not the model itself: Core stores what the customer decided, on what basis, across which dimensions, and enforcement derives framework compliance from correct records rather than bolting compliance onto dirty data.

Consent recorded here is what write-time event enforcement reads (see [Enforcement](#enforcement)): an identified event cannot enter Core without a consent decision that authorizes it.

**Base path:** `/api/v1/consent`

**Authentication:** All requests require a signed JWT in the `Authorization` header. See [Authentication](#authentication) below.

---

## Authentication

Every request must include a valid Ed25519-signed JSON Web Token (JWT) in the `Authorization` header using the Bearer scheme:

```
Authorization: Bearer <jwt>
```

### Registering A Vertical

Before a vertical can call Core, it must be registered:

1. The vertical generates an Ed25519 keypair (private + public)
2. The vertical hosts its public key at a JWKS endpoint (RFC 8615, typically `/.well-known/jwks.json`)
3. The vertical is registered in Core's `registered_verticals` table with its slug and JWKS URL

Core fetches the public key from the vertical's JWKS endpoint to verify signatures. Public keys can be rotated by adding new ones to the JWKS document; old keys remain available until rotated out. Vertical lookups are cached in-process (5-minute TTL), so registry or key changes can take a few minutes to take effect on a running instance.

### Required JWT Claims

Tokens must contain these claims:

| Claim | Type | Description |
|-------|------|-------------|
| `iss` | string | Vertical slug (must match a registered, active vertical) |
| `sub` | string | Tenant UUID — the tenant this request authorizes |
| `iat` | number | Issued-at, Unix timestamp in seconds |
| `exp` | number | Expiry, Unix timestamp in seconds |

Additional claims (e.g., `jti`, custom claims) are allowed but ignored.

### Token Constraints

- **Algorithm:** Must be `EdDSA` (Ed25519). Other algorithms including `none`, `HS256`, and `RS256` are rejected.
- **Type:** Header `typ` must be `JWT`.
- **Key ID:** Header `kid` must be present and must match a key in the issuer's JWKS.
- **Clock skew tolerance:** 30 seconds, both directions (early `iat` and late `exp`).
- **Maximum lifetime:** 24 hours. Tokens with `exp - iat > 86400` are rejected.

The tenant for every operation is taken from the verified `sub` claim. It is never read from the request body or any untrusted header — a `tenant_id` supplied in a request body is ignored. A vertical cannot write to or read from a tenant other than the one its signed token addresses.

For a token-signing example, see `docs/api/events.md` (the same tokens work against every Core endpoint).

---

## POST /api/v1/consent

Records one consent decision or a batch (max 100) for the authenticated tenant. Every record enters the append-only `consent_records` history; records currently in effect also upsert the `current_consent` projection **in the same transaction**, so the projection can never disagree with the history.

There is no client idempotency key (deliberate — see [Behavior Notes](#no-idempotency-key)); every accepted record creates a new history row.

### Request

**Method:** POST
**Path:** `/api/v1/consent`

**Headers:**

| Header           | Required | Value                                                  |
|------------------|----------|--------------------------------------------------------|
| `Content-Type`   | yes      | `application/json` (checked case-insensitively; must be present) |
| `Authorization`  | yes      | `Bearer <jwt>` — see Authentication above              |

Every response carries an `X-Service: threados-core` response header.

### Body Schema

The body is either a single consent record object or an array of record objects. Each record fully specifies all five consent dimensions (Bible Decision 13) — a decision spanning multiple channels or purposes is recorded as multiple records.

| Field             | Type        | Required | Constraints |
|-------------------|-------------|----------|-------------|
| `identity_id`     | UUID string | yes      | Core-owned identity UUID (from the identity API). Must exist for this tenant and not be soft-deleted. Normalized to lowercase. |
| `purpose`         | string      | yes      | One of: `marketing`, `personalization`, `analytics`, `service_operations`, `legal_compliance`, `fraud_prevention` |
| `vendor`          | string      | yes      | Opaque vendor identifier, non-empty after trim, ≤ 200 chars. Core does not maintain a vendor registry; the vertical owns vendor naming. |
| `channel`         | string      | yes      | One of: `email`, `sms`, `voice`, `push`, `mail`, `in_app` |
| `data_category`   | string      | yes      | One of: `behavioral`, `pii`, `location`, `financial`, `health` |
| `jurisdiction`    | string      | yes      | ISO 3166 format: a two-letter country code with an optional subdivision suffix (`US`, `US-CA`, `DE`, `GB-SCT`). Case-insensitive on input, normalized to uppercase — the canonical form of the owning standard, the same posture as UUID lowercasing. Format check only; Core does not maintain the country list. |
| `state`           | string      | yes      | One of: `granted`, `denied`, `withdrawn` — what the customer decided. |
| `consent_basis`   | string      | yes      | One of: `active_consent`, `documented_opt_in`, `legitimate_interest`, `contract`, `legal_obligation`, `undocumented` — the epistemic status of Core's knowledge of the decision (Bible Decision 14). |
| `captured_via`    | string      | yes      | One of: `web_form`, `email_response`, `phone`, `in_person`, `imported`, `api_direct`, `paper_form` |
| `capture_context` | string      | yes      | Non-empty after trim, ≤ 2000 chars. Free-text description of how the decision was captured. **PII-scanned** (same scanner as event properties): emails, formatted phone numbers, and SSNs are rejected, never echoed. |
| `reason`          | string      | yes      | Non-empty after trim, ≤ 2000 chars. Free-text rationale for recording the decision. **PII-scanned**, same rules. |
| `effective_from`  | string      | yes      | ISO 8601 timestamp — when the decision's validity begins (valid time). Parsed and normalized to a canonical ISO string. May be in the past (backfilled/imported decisions) or the future (see [Documented Positions](#documented-positions)). |
| `effective_until` | string      | no       | ISO 8601 timestamp or `null`/absent (= open-ended). If present, must be strictly **after** `effective_from` (`temporal_invalid` otherwise — a zero-length validity window is a contradiction, not a decision). |

Notes:

- **`state` and `consent_basis` are orthogonal.** `state` is what the customer decided; `consent_basis` is how well Core's knowledge of that decision is documented. An opt-in imported from a legacy system where the paper trail is gone is `state: "granted", consent_basis: "undocumented"` — we believe they opted in, we cannot prove it. What such a record *authorizes* depends on the tenant's compliance posture (see [Enforcement](#enforcement)).
- Vocabulary values are exact-match: `Granted` and `EMAIL` are rejected (`invalid_value`, with the allowed values listed in the error).
- Unknown fields in a record are currently ignored (not rejected). Strict unknown-field rejection is tracked as future work. A `tenant_id` in the body is among the ignored fields — tenant scoping comes from the JWT alone.

### Batch vs Single

- A single record object and a one-element array are equivalent.
- Maximum **100 records** per request (`batch_too_large` above that). Consent arrives at human cadence, not telemetry cadence; the cap is deliberately lower than the events API's 500.
- An empty array is rejected (`empty_batch`).
- **Reject-all on any failure.** If any record fails validation or references an unknown identity, the entire request is rejected and nothing is written.
- **A batch MAY contain multiple records for the same dimension tuple.** A batch is a sequence of decisions applied in array order, so the **last record for a tuple wins the projection** (all of them enter the history). This is deliberate — unlike events, where a repeated idempotency key inside one request is ambiguous and rejected.

### Curl Example: Single Record

```bash
curl -X POST https://<core-host>/api/v1/consent \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <jwt>" \
  -d '{
    "identity_id": "<identity-uuid>",
    "purpose": "marketing",
    "vendor": "acme_dms",
    "channel": "email",
    "data_category": "behavioral",
    "jurisdiction": "US-CA",
    "state": "granted",
    "consent_basis": "active_consent",
    "captured_via": "web_form",
    "capture_context": "Preference center save from account settings page",
    "reason": "Customer opted in via preference center",
    "effective_from": "2026-06-28T15:04:05Z"
  }'
```

### Curl Example: Batch (A Preference-Center Sweep)

```bash
curl -X POST https://<core-host>/api/v1/consent \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <jwt>" \
  -d '[
    {
      "identity_id": "<identity-uuid>",
      "purpose": "marketing",
      "vendor": "acme_dms",
      "channel": "email",
      "data_category": "behavioral",
      "jurisdiction": "US",
      "state": "granted",
      "consent_basis": "active_consent",
      "captured_via": "web_form",
      "capture_context": "Preference center full save",
      "reason": "Customer updated all channel preferences",
      "effective_from": "2026-06-28T15:04:05Z"
    },
    {
      "identity_id": "<identity-uuid>",
      "purpose": "marketing",
      "vendor": "acme_dms",
      "channel": "sms",
      "data_category": "behavioral",
      "jurisdiction": "US",
      "state": "denied",
      "consent_basis": "active_consent",
      "captured_via": "web_form",
      "capture_context": "Preference center full save",
      "reason": "Customer updated all channel preferences",
      "effective_from": "2026-06-28T15:04:05Z"
    }
  ]'
```

### Successful Response

A successful request always returns **201 Created**: consent records are append-only with no idempotency key, so every success creates history rows — there is no 200-duplicate case like the events API's.

```json
{
  "results": [
    { "record_id": "<uuid>", "projection": "created" },
    { "record_id": "<uuid>", "projection": "updated" }
  ],
  "created": 1,
  "updated": 1
}
```

**Response fields:**

| Field                  | Type   | Description |
|------------------------|--------|-------------|
| `results`              | array  | One entry per submitted record, in input order. |
| `results[].record_id`  | string | Core's generated primary key for the new `consent_records` history row. |
| `results[].projection` | string | What happened to `current_consent`: `created` (new projection row), `updated` (superseded an existing row), or `none` (entered history without touching the projection). |
| `created`              | int    | Count of new projection rows. |
| `updated`              | int    | Count of superseded projection rows. |

`projection: "none"` is a meaningful signal, not a failure: the record is durably in the history but did not change what is currently in effect. It happens when the record is future-dated, already expired at write time, or older (by `effective_from`) than the currently-projected decision for its tuple. See [Documented Positions](#documented-positions) — several deliberate semantics surface through this value.

### Error Responses

All errors return the standard error body (`code`, `message`, `details`); recording rejections carry the fixed message `consent recording rejected` with per-field/per-record `details`.

#### Authentication errors (401 Unauthorized)

Identical to the events API: `missing_auth`, `invalid_auth_format`, `token_malformed`, `unknown_issuer`, `unknown_key`, `invalid_signature`, `token_expired`, `invalid_claims`. See `docs/api/events.md` for the full table.

#### Request errors (400 / 413 / 415)

| Status | Error code              | Cause                                                |
|--------|-------------------------|------------------------------------------------------|
| 400    | `invalid_json`          | Request body is not valid JSON (syntax error)        |
| 400    | `invalid_body_type`     | Body parsed as JSON but the top-level type is not an object or array |
| 400    | `validation_failed`     | One or more records failed field validation. See `details`. |
| 413    | `payload_too_large`     | Request body exceeds 100 KB                          |
| 415    | `unsupported_media_type`| `Content-Type` is not `application/json`             |

#### Resource errors (404)

| Status | Error code              | Cause                                                |
|--------|-------------------------|------------------------------------------------------|
| 404    | `tenant_not_found`      | The tenant UUID in the JWT `sub` claim does not exist. 404 is reserved exclusively for this case (the Core-wide 404-vs-422 convention; see `docs/api/events.md`). |

#### Semantic errors (422 Unprocessable Entity)

| Status | Error code              | Cause                                                |
|--------|-------------------------|------------------------------------------------------|
| 422    | `identity_not_found`    | A record references an `identity_id` that does not exist (or is soft-deleted) for this tenant. An identity in another tenant is indistinguishable from one that does not exist. See `details` for the failing index. |

#### Server errors (503)

| Status | Error code              | Cause                                                |
|--------|-------------------------|------------------------------------------------------|
| 503    | `service_unavailable`   | Core cannot verify the request (e.g., JWKS endpoint unreachable) or the database is temporarily unavailable. Retry the request. |

### Validation Error Details

The `details` array carries one entry per problem, shaped `{ field, code, message, index? }` where `index` is the zero-based record position in a batch. Validation collects errors across all records — a single rejected request reports every problem at once. PII findings report the field, never the offending value.

Detail codes specific to or notable on this endpoint:

| Code                          | Meaning                                                        |
|-------------------------------|---------------------------------------------------------------|
| `missing`                     | A required field is absent or empty after trim                 |
| `invalid_type`                | A field has the wrong JSON type                                |
| `invalid_format`              | A field does not match its expected format (UUID, ISO 8601)    |
| `invalid_value`               | A vocabulary field's value is not in the controlled vocabulary (allowed values listed in the message) |
| `invalid_jurisdiction_format` | `jurisdiction` is not an ISO 3166 country / country-subdivision code |
| `temporal_invalid`            | `effective_until` is not strictly after `effective_from`       |
| `too_long`                    | A field exceeds its maximum length                             |
| `pii_detected`                | `capture_context` or `reason` contains data matching a PII pattern |
| `batch_too_large`             | More than 100 records in one request                           |
| `empty_batch`                 | The request array contained zero records                       |
| `invalid_body_type`           | Top-level body is neither an object nor an array               |
| `identity_not_found`          | Referenced `identity_id` does not exist for the tenant         |

---

## GET /api/v1/consent/:identity_id

Reads the identity's current consent state from the `current_consent` projection; optionally its full history, paginated.

### Request

**Method:** GET
**Path:** `/api/v1/consent/:identity_id`

**Query parameters:**

| Parameter | Required | Constraints |
|-----------|----------|-------------|
| `include` | no       | The only supported value is `history`. Anything else — including case variants like `History` — is rejected (`invalid_value`), not ignored: a typo silently returning no history would mislead. |
| `limit`   | no       | History page size, default 100, range 1–500. Only valid together with `include=history` (rejected otherwise). Must be a **canonical decimal-digit string** (`/^\d+$/`): `1e2`, `0x64`, and whitespace-padded forms are rejected (`invalid_format`); out-of-range values are rejected (`invalid_value`), never silently clamped. |
| `before`  | no       | ISO 8601 timestamp; returns only history records with `recorded_at` strictly before it (exclusive keyset cursor). Only valid together with `include=history`. |

`identity_id` must be a valid UUID (400 `validation_failed` otherwise). The identity must exist for the authenticated tenant (422 `identity_not_found` otherwise — same 404-vs-422 convention as everywhere in Core).

### Response

**200 OK**, shaped:

```json
{
  "identity_id": "<uuid>",
  "consent": {
    "marketing": [
      {
        "vendor": "acme_dms",
        "channel": "email",
        "data_category": "behavioral",
        "jurisdiction": "US",
        "state": "granted",
        "consent_basis": "active_consent",
        "effective_from": "2026-06-28T15:04:05.000Z",
        "effective_until": null,
        "source_record_id": "<consent_records uuid>"
      },
      { "...": "one entry per dimension tuple with a currently-effective decision" }
    ],
    "analytics": [ { "...": "..." } ]
  }
}
```

The top level of `consent` is keyed by **purpose** — the axis verticals query by ("what may I do for marketing?") — with each entry carrying the full remaining dimension tuple flat. Only rows whose validity window covers *now* appear: `effective_from <= now` and (`effective_until` null or in the future). `effective_until` is returned on each entry so bounded grants show their end. `source_record_id` links each projected decision to the exact history record that produced it.

**An identity with no consent rows returns 200 with `"consent": {}`** — not 404, not 422. "No record" is a valid, meaningful consent state (it means **no consent**, the strictest default), not a missing resource. 404 stays reserved for the tenant.

### History

With `?include=history`, the response adds:

```json
{
  "history": {
    "records": [
      {
        "record_id": "<uuid>",
        "purpose": "marketing",
        "vendor": "acme_dms",
        "channel": "email",
        "data_category": "behavioral",
        "jurisdiction": "US",
        "state": "withdrawn",
        "consent_basis": "active_consent",
        "captured_via": "phone",
        "capture_context": "...",
        "reason": "...",
        "effective_from": "2026-06-01T00:00:00.000Z",
        "effective_until": null,
        "recorded_at": "2026-06-28T15:04:05.911Z"
      }
    ],
    "has_more": true
  }
}
```

- Records are ordered `recorded_at DESC` (system time — the order Core learned of decisions), with `record_id DESC` as a stable tiebreaker for records written in one batch (a batch shares a single `recorded_at`: one transaction, one `CURRENT_TIMESTAMP`).
- `has_more` reports whether older records exist beyond this page. To fetch the next page, pass the **oldest `recorded_at` you have seen** as `before`.
- **Timestamp-tie caveat (documented behavior):** the cursor is exclusive on `recorded_at` alone. Records sharing the cursor's exact timestamp — same-batch siblings — are excluded along with it, so a page boundary landing *inside* a batch skips that batch's remaining rows. Callers paging deep histories should raise `limit` rather than walking tight pages; a composite `(recorded_at, record_id)` cursor is the tracked upgrade if this bites in practice.

### Curl Example

```bash
curl "https://<core-host>/api/v1/consent/<identity-uuid>?include=history&limit=50" \
  -H "Authorization: Bearer <jwt>"
```

### Error Responses

| Status | Error code           | Cause                                                        |
|--------|----------------------|--------------------------------------------------------------|
| 400    | `validation_failed`  | Malformed `identity_id`, unknown `include` value, bad/out-of-range `limit`, unparseable `before`, or `limit`/`before` without `include=history`. See `details`. |
| 401    | (auth codes)         | Same table as POST.                                          |
| 404    | `tenant_not_found`   | The tenant in the JWT `sub` claim does not exist.            |
| 422    | `identity_not_found` | The identity does not exist (or is soft-deleted) for this tenant. Distinct from the empty-consent 200: the *identity* is the resource; its consent state is data. |
| 503    | `service_unavailable`| Database temporarily unavailable. Retry.                     |

---

## Enforcement

Consent recorded through this API is what gates event capture (Bible Decision 15): every **identified** event is checked before storage, inside the capture transaction. This section is the reference for how a consent record translates into authorization. The rule map below is reproduced from `src/lib/enforcement.js`, which is **canonical** — if this document and that file ever disagree, the code is right and this document has rotted.

### Invariants (every posture)

1. **No `current_consent` row for the relevant dimension tuple → rejected.** No record means no consent — the strictest, framework-agnostic default.
2. **`state` ∈ {`denied`, `withdrawn`} → rejected.**
3. **`state = granted` → basis × posture × purpose decides** (the map below).

### The Rule Map (basis × posture)

Each cell lists the purposes a **granted** record with that basis may authorize under that posture:

| basis \ posture       | Strict          | Standard        | Legacy          |
|-----------------------|-----------------|-----------------|-----------------|
| `active_consent`      | all purposes    | all purposes    | all purposes    |
| `documented_opt_in`   | all purposes    | all purposes    | all purposes    |
| `legitimate_interest` | rejected        | operational¹    | operational¹    |
| `contract`            | rejected        | `service_operations` only | `service_operations` only |
| `legal_obligation`    | `legal_compliance` only | `legal_compliance` only | `legal_compliance` only |
| `undocumented`        | rejected        | rejected        | limited-use²    |

¹ **Operational** = `service_operations`, `fraud_prevention`. Analytics is deliberately excluded — consent-gated under every posture.
² **Limited-use** = `service_operations`, `legal_compliance`, `fraud_prevention`. Never marketing/personalization/analytics.

The tenant's posture is `tenants.compliance_posture` (Strict / Standard / Legacy, Bible Decision 14), declared at onboarding. The map is **static Core code, not per-tenant configurable**: tenants choose a posture; they do not edit the law. Unknown posture/basis/purpose values fail closed (deny).

### What Capture Implicates

- **`data_category`:** pinned to `'behavioral'` — event capture is by definition behavioral data collection (PII structurally cannot be in events, Decision 10).
- **`purpose`:** declared per event type in the registry (`event_type_registry.implicated_purpose`), default `'analytics'` — the most consent-gated capture purpose, so undeclared event types fail closed. Purpose cannot be a constant: an order-status event implicates `service_operations` while a page view implicates `analytics`, and only the vertical knows which (Decision 13: verticals declare which regulatory regimes apply to their events).
- **`vendor`, `channel`, `jurisdiction`:** **not implicated at capture.** The processor at capture time is Core itself; these dimensions govern outbound use and are enforced at those touchpoints. Instead, all matching rows across them are evaluated with **deny-precedence**: an explicit denial or withdrawal on *any* row matching (identity, purpose, behavioral) rejects capture, even if another row is granted. Rationale: a customer who has denied *anyone* this purpose over this data plausibly means "stop collecting" — the fail-closed, customer-over-client reading (Decision 22).

Among granted rows passing the map, the one with the **latest `effective_from`** authorizes (the same supersession rule the projection uses) and is cited in the snapshot.

### Fail Modes (fail-closed, fail-honest)

- **403 `consent_denied`** — well-formed request, everything it references exists, the customer has not consented (no record, denial/withdrawal, or an insufficient basis for the purpose under the tenant's posture). Reject-all: one non-consented event rejects the whole batch. The per-event detail names the purpose and machine reason (`no_consent_record`, `consent_denied`, `consent_withdrawn`, `basis_insufficient`) and points at this API as the diagnostic — it deliberately does **not** name which consent row decided; the vertical is authorized to read the identity's full consent state here, so nothing is lost.
- **503 `consent_check_unavailable`** — the consent lookup itself failed (infrastructure). The transaction rolled back; nothing was stored. Retry is appropriate.

### The Snapshot

Every persisted event carries its consent evaluation in `consent_snapshot`:

```json
{
  "status": "granted",
  "posture": "strict",
  "purpose": "analytics",
  "basis": "active_consent",
  "source_record_id": "<the consent_records row that authorized capture>",
  "evaluated_at": "2026-07-01T00:00:00.000Z"
}
```

Anonymous events (no `identity_id`) are not consent-rejected — Decision 15 assigns them to the 30-day holding pattern (Decision 21, designed, not yet implemented) — and carry `{ "status": "anonymous_holding", "reason": "pre_identification_holding_pending_decision_21" }`.

Snapshots written by the Step 6 backfill additionally carry `"backfilled": true` and `"evaluated_as_of": "<event_timestamp>"` (the instant the point-in-time reconstruction evaluated against), so backfilled evaluations are permanently distinguishable from live ones in audit review. Backfill-denied events carry `"status": "denied"` with the reason and are expired out of retention.

---

## Documented Positions

These are deliberate policy, verified under adversarial testing (Step 7 Session 5), not accidents of implementation. Each has a test asserting it.

### Backdated Withdrawal vs A Later-Starting Decision

Current consent is **the decision with the latest valid-time start**. A withdrawal recorded later but backdated to before an existing grant's `effective_from` *rewrites history* — point-in-time evaluation, the backfill, and audit reconstruction all see the withdrawal for the window it claims — but it **cannot override a decision with a later `effective_from`** in the projection, and live enforcement continues to honor the grant.

The "I never wanted this" case therefore has two distinct encodings:

- **To stop processing now:** record the withdrawal with `effective_from = now` (or later than the grant's). It wins — latest valid-time start — and the projection updates.
- **To correct the historical record:** backdate `effective_from`. This changes what retrospective evaluation concludes about the past, and only that.

The API's signal that a write did not change current state is `projection: "none"` in the POST response. A vertical that backdates a withdrawal expecting it to stop current processing will get `projection: "none"` — check for it.

### Future-Dated Records: Write-Time Activation

A record whose `effective_from` is in the future enters the history (`projection: "none"`) and is fully honored by point-in-time evaluation and the backfill — but it does **not** activate live enforcement when its window later starts. Live activation requires the window to have started at write time. A vertical wanting scheduled activation writes the record at activation time; **scheduling is module-layer responsibility** (modules own workflow; Core owns truth). If verticals demonstrate real demand for Core-side activation, a projection-refresh sweep is the tracked upgrade path.

### No Plausibility Bound On `effective_from`

Any parseable ISO 8601 instant is accepted — epoch 0 included. Imported legacy consent is old by nature; a 1998 paper opt-in is a real thing ThreadOS must represent, so Core imposes no floor. A fat-fingered year (0206 for 2026) is the vertical's data-integrity problem at the module layer, which is exactly where vertical-specific plausibility rules belong.

### Expiry Semantics

A grant whose `effective_until` passes becomes **invisible to enforcement and reads by clock-tick** — no superseding write required. The projection stores the validity window and every reader filters to rows whose window covers now; an expired row is semantically "no row", and no row means no consent. Two consequences:

- The physical projection row may linger until the next write for its tuple supersedes it; the reader filters make it inert. Do not read `current_consent` directly without the window filter — use this API or `getCurrentConsent`.
- **A lapsed incumbent holds no supersession rights:** a currently-valid record can replace an expired projection row even with an *earlier* `effective_from` (e.g. a revived open-ended import arriving after a bounded grant expired). The latest-start rule applies among *live* decisions only.

---

## Behavior Notes

### Append-Only: No Update, No Delete

There is no `PUT`, `PATCH`, or `DELETE` on this surface, deliberately. A consent change is a **new record** that supersedes in the projection; history rows are never modified (Bible Decision 13 — the history is the audit trail). Right-to-erasure is a separate workflow operating at the identity level (Decision 6 cascade semantics), tracked for the retention/erasure implementation before production — it is not expressed as consent-record deletion.

### No Idempotency Key

Unlike events, consent records carry no client idempotency key (settled Step 7 Session 2 design). Duplicate submissions converge in the projection (same tuple, same state) and are benign noise in the append-only history — the same decision asserted twice, with point-in-time reconstruction unaffected. Verticals own retry hygiene; if retry patterns ever produce duplicate history rows that matter for audit review, adding a key is tracked as the follow-up.

### Point-In-Time Reconstruction And The Backfill

The bitemporal history supports answering "what consent was in effect at instant T?" — for each dimension tuple, the record with the latest `effective_from` among those whose window covers T. This is what `scripts/backfill-consent-snapshots.js` does for events captured before write-time enforcement existed: it evaluates each event against the consent in effect **at its `event_timestamp`** (not today's projection — "was there consent when it happened?", not "would we accept it now?"), under the same rule map. Idempotent, `--dry-run` supported. See the Consent Enforcement section of `docs/api/events.md` for disposition details.

### Tenant Isolation

Everything is scoped to the tenant in the JWT `sub` claim: identity checks, history inserts, projection upserts, reads. Identities in tenant A and tenant B are separate even if they represent the same human; consent given to one tenant says nothing about another (Bible Decision 4). Cross-tenant reads and writes are structurally impossible — an identity in another tenant is indistinguishable from one that does not exist (422).

### Synchronous Projection Maintenance

`consent_records` inserts and `current_consent` upserts happen in **one transaction** (Bible Decision 15): the projection can never disagree with the history, and a 201 means both are durably written (Decision 17 — no async-write-ahead). The projection upsert applies, per record: only records whose validity window has started enter; the latest `effective_from` wins a tuple; a lapsed incumbent is treated as vacant (see [Expiry Semantics](#expiry-semantics)).

### Registry Management

Consent purposes for event enforcement are declared on event-type registry rows (`implicated_purpose`). Registry entries are still created by direct `INSERT` — the same known gap documented in `docs/api/events.md` (Behavior Notes → Event Type Registry); it is not restated here.

---

## Implementation References

- Consent business logic (validation, recording, projection maintenance, reads, pagination): `src/lib/consent.js`
- Route handlers and status-code mapping: `src/routes/consent.js`
- Enforcement rule map and evaluators (**canonical** for the map above): `src/lib/enforcement.js`
- Consent check inside event capture: `src/lib/events.js` (`checkConsent`)
- PII scanner (shared with event properties): `src/lib/pii.js`
- Pre-enforcement event backfill: `scripts/backfill-consent-snapshots.js`
- Schema: `db/schema.sql` Section 5; migrations 005 (data model), 006 (`implicated_purpose`), 007 (`effective_until` on the projection) in `db/migrations.sql`
- Shared field validators: `src/lib/validation.js`
- Auth middleware (`requireSignedRequest`): `src/middleware/auth.js`
- DB pool and `withTransaction`: `src/lib/db.js`

For architectural context, see `THREADOS_BIBLE.md` (Decisions 4, 7, 13, 14, 15).

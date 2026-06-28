# Events API

ThreadOS Core's event capture API persists behavioral events for a tenant. Verticals call it to record what a customer did (page views, purchases, engagement signals) against a Core-owned identity, an opaque session, or a device fingerprint. Events carry behavioral data only — customer-identifying PII has exactly one path into Core, the identity API, and the events endpoint rejects PII it finds in event properties. The endpoint accepts a single event or a batch, validates every event strictly, and persists synchronously (a 2xx means the data is durably written).

**Base path:** `/api/v1/events`

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

The tenant for every operation is taken from the verified `sub` claim. It is never read from the request body or any untrusted header. A vertical cannot write to a tenant other than the one its signed token addresses.

### Example: Signing A Token (Node.js)

```javascript
const crypto = require('crypto');
const fs = require('fs');

const privateKey = fs.readFileSync('vertical-private.pem', 'utf8');

const header = {
    alg: 'EdDSA',
    typ: 'JWT',
    kid: '<your key id>',
};

const now = Math.floor(Date.now() / 1000);
const payload = {
    iss: 'your-vertical-slug',
    sub: '<tenant-uuid>',
    iat: now,
    exp: now + 3600,
};

const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
const signingInput = headerB64 + '.' + payloadB64;

const keyObject = crypto.createPrivateKey(privateKey);
const signature = crypto.sign(null, Buffer.from(signingInput), keyObject);
const signatureB64 = signature.toString('base64url');

const jwt = signingInput + '.' + signatureB64;
```

Sign a fresh token for each call or batch of calls. Tokens are short-lived by design.

---

## POST /api/v1/events

Captures one event or a batch of events for the authenticated tenant. Validates every event, confirms each `(event_name, event_category)` pair is registered for the tenant, confirms any referenced `identity_id` exists, then persists all events in a single transaction.

The endpoint is idempotent on the client-provided `event_id`: submitting the same `event_id` again is a no-op success, not a duplicate row.

### Request

**Method:** POST
**Path:** `/api/v1/events`

**Headers:**

| Header           | Required | Value                                                  |
|------------------|----------|--------------------------------------------------------|
| `Content-Type`   | yes      | `application/json` (checked case-insensitively; must be present) |
| `Authorization`  | yes      | `Bearer <jwt>` — see Authentication above              |

Every response (including error responses produced before any route runs) carries an `X-Service: threados-core` response header.

### Body Schema

The body is either a single event object or an array of event objects. Each event object has these fields:

| Field                | Type        | Required | Constraints |
|----------------------|-------------|----------|-------------|
| `event_id`           | UUID string | yes      | Client-provided idempotency key. Must be a valid UUID; normalized to lowercase. |
| `event_name`         | string      | yes      | Non-empty after trim, ≤ 100 chars. Must be a registered event type for the tenant. |
| `event_category`     | string      | yes      | Non-empty after trim, ≤ 50 chars. Must match the category the event name is registered under. |
| `source_type`        | string      | yes      | Non-empty after trim, ≤ 50 chars. Free-form (e.g. `web`, `ios`, `server`). |
| `event_timestamp`    | string      | yes      | ISO 8601 timestamp. Parsed and normalized to a canonical ISO string before storage. |
| `identity_id`        | UUID string | †        | Core-owned identity UUID (from the identity API). If present, must exist for this tenant. |
| `session_id`         | string      | †        | Opaque external identifier, ≤ 200 chars, no control characters. Core does not own its format. |
| `device_fingerprint` | string      | †        | Opaque external identifier, ≤ 200 chars, no control characters. Core does not own its format. |
| `source_id`          | string      | no       | ≤ 100 chars. Free-form identifier for the source (e.g. a page or campaign id). |
| `properties`         | JSON object | no       | Arbitrary behavioral data. Scanned for PII (see [PII Detection](#pii-detection)). Defaults to `{}` when absent. |

† **At least one of** `identity_id`, `session_id`, or `device_fingerprint` is required. An event with none of the three is rejected (`missing_identifier`).

Notes:

- String fields are trimmed; an all-whitespace value for a required field is treated as missing.
- `identity_id` accepts `null`/`""`/absent as "not provided"; if a non-empty value is present it must be a valid UUID.
- `source_id`, `session_id`, and `device_fingerprint` accept `null`/`""`/absent as "not provided".
- Unknown fields in an event object are currently ignored (not rejected). Strict unknown-field rejection is tracked as future work.

### Batch vs Single

- A single event object and a one-element array are equivalent.
- Maximum **500 events** per request (`batch_too_large` above that).
- An empty array is rejected (`empty_batch`).
- **Reject-all on any validation failure.** If any event in the batch fails validation, registry check, or identity check, the entire request is rejected and nothing is written. There are no partial writes.

### Curl Example: Single Event

```bash
curl -X POST https://<core-host>/api/v1/events \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <jwt>" \
  -d '{
    "event_id": "11111111-1111-4111-8111-111111111111",
    "event_name": "page_viewed",
    "event_category": "engagement",
    "source_type": "web",
    "event_timestamp": "2026-06-28T15:04:05Z",
    "identity_id": "<identity-uuid>",
    "properties": { "path": "/pricing", "referrer": "search" }
  }'
```

### Curl Example: Batch Of Two

```bash
curl -X POST https://<core-host>/api/v1/events \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <jwt>" \
  -d '[
    {
      "event_id": "11111111-1111-4111-8111-111111111111",
      "event_name": "page_viewed",
      "event_category": "engagement",
      "source_type": "web",
      "event_timestamp": "2026-06-28T15:04:05Z",
      "session_id": "sess_abc123"
    },
    {
      "event_id": "22222222-2222-4222-8222-222222222222",
      "event_name": "checkout_started",
      "event_category": "commerce",
      "source_type": "web",
      "event_timestamp": "2026-06-28T15:06:12Z",
      "identity_id": "<identity-uuid>",
      "device_fingerprint": "fp_9f8e7d",
      "properties": { "cart_value": 149.00, "currency": "USD" }
    }
  ]'
```

### Successful Response

The response reports the per-event outcome and aggregate counts:

```json
{
  "results": [
    { "event_id": "uuid", "status": "created", "id": "<core-primary-key>" },
    { "event_id": "uuid", "status": "duplicate" }
  ],
  "created": 1,
  "duplicates": 1
}
```

**Response fields:**

| Field                | Type   | Description |
|----------------------|--------|-------------|
| `results`            | array  | One entry per submitted event, in input order. |
| `results[].event_id` | string | The `event_id` from the request. |
| `results[].status`   | string | `created` (newly persisted) or `duplicate` (an event with this `event_id` already existed). |
| `results[].id`       | string | Core's generated primary key. Present only for `created` events. |
| `created`            | int    | Count of newly persisted events. |
| `duplicates`         | int    | Count of events that already existed. |

**201 vs 200:** The status code is **201 Created** when at least one event was newly persisted (`created > 0`), and **200 OK** when every event in the request was an idempotent duplicate. Mixed batches return 201.

All new (201):

```json
{
  "results": [
    { "event_id": "11111111-1111-4111-8111-111111111111", "status": "created", "id": "a1..." },
    { "event_id": "22222222-2222-4222-8222-222222222222", "status": "created", "id": "a2..." }
  ],
  "created": 2,
  "duplicates": 0
}
```

All duplicate (200):

```json
{
  "results": [
    { "event_id": "11111111-1111-4111-8111-111111111111", "status": "duplicate" },
    { "event_id": "22222222-2222-4222-8222-222222222222", "status": "duplicate" }
  ],
  "created": 0,
  "duplicates": 2
}
```

Mixed (201, because at least one was created):

```json
{
  "results": [
    { "event_id": "11111111-1111-4111-8111-111111111111", "status": "created", "id": "a1..." },
    { "event_id": "22222222-2222-4222-8222-222222222222", "status": "duplicate" }
  ],
  "created": 1,
  "duplicates": 1
}
```

### Error Responses

All errors return a JSON body with this structure:

```json
{
  "error": {
    "code": "string_code",
    "message": "human-readable description",
    "details": [ ... ]
  }
}
```

For capture rejections (validation, registry, identity, tenant), the top-level `code` is the rejection category, the top-level `message` is the fixed string `event capture rejected`, and `details` carries the specific per-field/per-event errors. Errors raised earlier in the pipeline (auth, content type, body parsing) return their own `code` and `message` and have no `details`.

#### Authentication errors (401 Unauthorized)

| Error code              | Cause                                                  |
|-------------------------|--------------------------------------------------------|
| `missing_auth`          | `Authorization` header is absent                       |
| `invalid_auth_format`   | `Authorization` is not in `Bearer <token>` format, or the token is empty |
| `token_malformed`       | Token structure is wrong, or `iss`/`kid` missing       |
| `unknown_issuer`        | `iss` claim does not match a registered, active vertical |
| `unknown_key`           | `kid` in token header does not match any key in the issuer's JWKS |
| `invalid_signature`     | Signature verification failed                          |
| `token_expired`         | Token's `exp` is in the past (beyond skew tolerance)   |
| `invalid_claims`        | Required claims missing or invalid (includes lifetime > 24h) |

#### Request errors (400 / 413 / 415)

| Status | Error code              | Cause                                                |
|--------|-------------------------|------------------------------------------------------|
| 400    | `invalid_json`          | Request body is not valid JSON (syntax error)        |
| 400    | `invalid_body_type`     | Body parsed as JSON but the top-level type is not an object or array (e.g. a bare string, number, boolean, or null) |
| 400    | `validation_failed`     | One or more events failed field validation. See `details`. |
| 413    | `payload_too_large`     | Request body exceeds 100 KB                          |
| 415    | `unsupported_media_type`| `Content-Type` is not `application/json`             |

#### Resource errors (404)

| Status | Error code              | Cause                                                |
|--------|-------------------------|------------------------------------------------------|
| 404    | `tenant_not_found`      | The tenant UUID in the JWT `sub` claim does not exist |

#### Semantic errors (422 Unprocessable Entity)

| Status | Error code              | Cause                                                |
|--------|-------------------------|------------------------------------------------------|
| 422    | `unregistered_event`    | An event references an `event_name`/`event_category` pair that is not registered (or whose category contradicts the registration) for this tenant. See `details`. |
| 422    | `identity_not_found`    | An event references an `identity_id` that does not exist (or is soft-deleted) for this tenant. See `details`. |

#### Server errors (503)

| Status | Error code              | Cause                                                |
|--------|-------------------------|------------------------------------------------------|
| 503    | `service_unavailable`   | Core cannot verify the request (e.g., JWKS endpoint unreachable) or the database is temporarily unavailable. Retry the request. |

#### The 404-vs-422 Convention

This is a deliberate, Core-wide rule (`statusForRejection` in `src/routes/events.js`):

- **404 is reserved exclusively for the tenant named by the JWT `sub` claim.** It means "the tenant your token addresses does not exist." Nothing else returns 404.
- **422 is for every other reference, evaluated within an authenticated, existing-tenant context, that doesn't resolve or violates a registry constraint** — an unregistered event type, an `event_category` that contradicts the registration, or an `identity_id` not present in this tenant. The payload is well-formed; what it points at is the problem.
- **400 is for a malformed payload** — missing or ill-typed fields, a bad timestamp, PII in properties, or a wrong top-level body type. The client can fix it by correcting the bytes it sent.

In short: 404 = "the tenant in your token is gone," 422 = "your well-formed request references something else that isn't there / isn't allowed," 400 = "your payload is malformed."

### Validation Error Details

For capture rejections, the `details` array contains one entry per problem found. Each entry has the same shape as the identity API's validation details, plus an `index` field when the request was a batch:

```json
{
  "error": {
    "code": "validation_failed",
    "message": "event capture rejected",
    "details": [
      {
        "field": "event_name",
        "code": "missing",
        "message": "event_name is required",
        "index": 0
      },
      {
        "field": "properties.email",
        "code": "pii_detected",
        "message": "properties may not contain PII (email detected at properties.email); route identifying data through the identity API",
        "index": 1
      }
    ]
  }
}
```

- `field` — the offending field, or a JSON path within `properties` for PII findings (e.g. `properties.user.contact`, `properties.items[2]`). For an event-level problem the field is `event`; for batch/body-level problems it is `body`.
- `code` — a machine-readable error code (see below).
- `message` — a human-readable description. PII messages report the path of detection but **never** echo the offending value.
- `index` — the zero-based position of the event within the request. Present for per-event errors so a vertical can locate which event in a batch failed. Batch/body-level errors (`empty_batch`, `batch_too_large`) have no `index`.

Validation collects errors across all events rather than stopping at the first — a single rejected request can report every problem at once.

Common detail codes:

| Code                          | Meaning                                                        |
|-------------------------------|---------------------------------------------------------------|
| `missing`                     | A required field is absent or empty after trim                 |
| `missing_identifier`          | None of `identity_id`, `session_id`, `device_fingerprint` provided |
| `invalid_type`                | A field has the wrong JSON type                                |
| `invalid_format`              | A field does not match its expected format (e.g. UUID, ISO 8601) |
| `invalid_characters`          | A string contains control characters that are not allowed      |
| `too_long`                    | A field exceeds its maximum length                            |
| `pii_detected`                | `properties` (a value or a key) contains data matching a PII pattern |
| `duplicate_event_id_in_batch` | The same `event_id` appears more than once in one request      |
| `batch_too_large`             | More than 500 events in one request                            |
| `empty_batch`                 | The request array contained zero events                        |
| `invalid_body_type`           | Top-level body is neither an object nor an array               |
| `unregistered_event`          | `event_name` is not registered for the tenant                  |
| `event_category_mismatch`     | `event_name` is registered, but under a different category     |
| `identity_not_found`          | Referenced `identity_id` does not exist for the tenant         |

(`unregistered_event` and `identity_not_found` appear both as the top-level rejection `code` and within `details`; `event_category_mismatch` appears only in `details` under a top-level `unregistered_event` rejection.)

---

## Behavior Notes

### Event Type Registry

Events must reference an `(event_name, event_category)` pair that is registered and active for the calling tenant (Bible Decision 8). The check runs against the `event_type_registry` table: the event name must exist for the tenant with `is_active = true`, and the supplied `event_category` must equal the category the name is registered under. An unknown name returns `unregistered_event`; a known name with the wrong category returns `event_category_mismatch`. Both reject the whole batch with a 422.

**Known gap — registry management.** Today, registry entries are created by direct `INSERT` into `event_type_registry`. There is no API for managing the registry. Productizing this — whether as an admin endpoint on Core or as an abstraction in the vertical module layer — is a forward-looking engineering decision that has not been made. For now, seeding the registry is a manual database operation.

### Properties Schema

`properties` is an arbitrary JSON object. Beyond the PII scan, Core does **not** validate its contents: there is no field-level schema enforced per event type, and no type checking of individual property values. Bible Decision 8 specifies per-event-type schema validation as future work; it is not implemented. Until then, `properties` is stored as a typed JSONB blob as received.

### PII Detection

Core scans `properties` recursively before persisting — both property **values** and property **keys**, at any nesting depth, including inside arrays (Bible Decision 10). The patterns detected are:

- **Email addresses** — `local@domain.tld` shape, matched anywhere in a string.
- **US/NANP phone numbers** — only when visibly phone-formatted (parenthesized area code, or dash/dot/space separators), optionally with a `+1`/`1` country code. A bare 10-digit run like `5551234567` is intentionally **not** matched (it is just as likely an order number or id).
- **International phone numbers** — grouped E.164-style presentation (`+44 20 7946 0958`) and unseparated E.164 runs (`+442079460958`, a leading `+` followed by 8–15 digits).
- **US Social Security Numbers** — `###-##-####` with dash or space separators.

The detection is deliberately conservative-but-broad and biased toward under-detection: a false positive (e.g. a 10-digit order number that looks like a phone) forces a vertical to restructure a legitimate property, which is real friction, so the patterns require formatting before they fire. It is a gatekeeper, not a perfect classifier.

Any finding rejects the entire request with `pii_detected` errors (HTTP 400). The error reports the **path** of the detection so the vertical can locate the field; the offending value is **never** echoed back into the error or logs. When a property key itself is PII, the key is reported by position (`properties[key#N]`), again never by its text.

The rule this enforces: customer-identifying data routes through `POST /api/v1/identity/hash`; events carry behavioral data only.

### Identifier Rule

Every event requires at least one of `identity_id`, `session_id`, or `device_fingerprint`. Events failing this are rejected at validation (`missing_identifier`). `session_id` and `device_fingerprint` are opaque external identifiers — Core enforces only that they are non-empty, length-bounded (≤ 200 chars), control-character-free strings, not any particular format.

**Known gap — anonymous holding pattern.** Bible Decision 21 specifies a future dual-track scheme for events without an `identity_id` (30-day individual retention plus permanent aggregate counters). It is not implemented. All events currently persist with `retention_status = 'standard'`.

### Idempotency

`event_id` is a client-provided idempotency key. Submitting the same `event_id` more than once — whether across separate requests or within a single batch — does not create duplicate rows. The persistence layer uses `INSERT ... ON CONFLICT (tenant_id, event_id) DO NOTHING`: the first submission is canonical and is reported `created`; later submissions are reported `duplicate`.

The server does **not** compare request body content between submissions. The first body wins; a second submission with the same `event_id` but different fields is still a no-op `duplicate`, and the differing fields are ignored. This is the same model as Stripe idempotency keys.

Note the distinction from intra-batch duplicates: two events with the **same** `event_id` in **one** request are rejected as a validation error (`duplicate_event_id_in_batch`), not silently deduplicated. Within a single request, a repeated `event_id` is always a client bug — there is no defensible "first wins" interpretation — so Core rejects it rather than guessing.

### Batch Validation Contract

Any failure within a batch — field validation, intra-batch duplicate, registry check, or identity check — rejects the entire request. Nothing is written (reject-all, Bible Decision 7). Field-validation errors are collected across all events and returned together so the client sees every problem in one response rather than fixing them one at a time. (Registry and identity checks run after field validation passes, so their errors are returned on their own pass, not interleaved with field errors.)

### Tenant Isolation

Events are scoped to the tenant in the JWT `sub` claim. Registry checks, identity-existence checks, and inserts are all filtered by that tenant id. Cross-tenant access is structurally impossible: a vertical sees and writes only its own tenants' data, and the tenant is never taken from the request body.

### Consent Enforcement

Events currently persist with a placeholder consent snapshot:

```json
{ "status": "not_evaluated", "reason": "consent_enforcement_pending_step_7" }
```

The `events.consent_snapshot` column is non-null, so Core writes this explicit "not evaluated" marker rather than a fabricated granted/denied decision. Real write-time consent evaluation arrives in Step 7 (Bible Decision 15), which will also decide the disposition of the historical events written during Step 6 (findable by `consent_snapshot->>'status' = 'not_evaluated'`). Until then, events are captured but **not** consent-gated.

### Synchronous Persistence

The endpoint returns a 2xx only after all events in the request are durably written. The full pipeline — tenant check, registry check, identity check, inserts — runs inside a single database transaction; the batch commits all-or-nothing. There is no async-write-ahead pattern (Bible Decision 17). Async ingestion via Pub/Sub is tracked as future work, to be taken on when synchronous persistence shows scaling pain.

---

## Well-Known Endpoints

### GET /.well-known/jwks.json

Returns Core's own JWKS document (Core's public keys, for services that need to verify signatures Core itself produces). This is unrelated to the per-vertical JWKS endpoints Core fetches to verify incoming tokens. See `docs/api/identity.md` for the response shape.

---

## Implementation References

- Event capture business logic (validation, PII scan, registry/identity checks, persistence): `src/lib/events.js`
- Route handler and status-code mapping (`statusForRejection`): `src/routes/events.js`
- Shared field validators (`validateUuid`, `validateOptionalOpaqueId`): `src/lib/validation.js`
- PII hashing (identity API path): `src/lib/hashing.js`
- Auth middleware (`requireSignedRequest`): `src/middleware/auth.js`
- DB pool and `withTransaction`: `src/lib/db.js`

For architectural context, see `THREADOS_BIBLE.md` (Decisions 7, 8, 10, 17).

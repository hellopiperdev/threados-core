# Identity API

ThreadOS Core's identity API provides PII hashing and identity resolution. Verticals call these endpoints to convert customer PII into stable identity records without ever storing raw PII themselves.

**Base path:** `/api/v1/identity`

**Authentication:** Currently uses an `X-Tenant-Id` HTTP header for development. This will be replaced with JWT-based authentication before production deployment.

---

## POST /api/v1/identity/hash

Hashes PII and returns an identity record. If an identity already exists for the given tenant and identifiers, returns the existing one; otherwise creates a new identity.

This endpoint is idempotent: calling it multiple times with the same inputs returns the same identity record.

### Request

**Method:** POST
**Path:** `/api/v1/identity/hash`

**Headers:**

| Header           | Required | Value                                                  |
|------------------|----------|--------------------------------------------------------|
| `Content-Type`   | yes      | `application/json`                                     |
| `X-Tenant-Id`    | yes      | UUID identifying the tenant making the request         |

**Body:**

```json
{
  "email": "jane@example.com",
  "phone": "555-123-4567",
  "name": "Jane Doe"
}
```

| Field    | Type   | Required | Notes                                                      |
|----------|--------|----------|------------------------------------------------------------|
| `email`  | string | †        | Must be a valid email format. Case-insensitive normalization. |
| `phone`  | string | †        | Must contain 10–15 digits. Formatting characters allowed.   |
| `name`   | string | no       | Up to 200 characters. Cannot contain control characters.   |

† At least one of `email` or `phone` must be provided.

### Successful Response

For a new identity (201 Created):

```json
{
  "identity": {
    "id": "3e30843a-847d-486b-b5bb-a797c2e51884",
    "display_email": "j***@example.com",
    "display_phone": "***-***-4567",
    "display_name": "Jane Doe",
    "created": true
  }
}
```

For an existing identity (200 OK):

```json
{
  "identity": {
    "id": "3e30843a-847d-486b-b5bb-a797c2e51884",
    "display_email": "j***@example.com",
    "display_phone": "***-***-4567",
    "display_name": "Jane Doe",
    "created": false
  }
}
```

**Response fields:**

| Field            | Type        | Description                                          |
|------------------|-------------|------------------------------------------------------|
| `identity.id`    | UUID string | Stable identifier for this customer in this tenant   |
| `identity.display_email` | string \| null | Sanitized email for display (e.g., `j***@example.com`) |
| `identity.display_phone` | string \| null | Sanitized phone for display (e.g., `***-***-4567`) |
| `identity.display_name`  | string \| null | The name as provided, if any                  |
| `identity.created`       | boolean | `true` if a new identity was created, `false` if existing |

The response **never contains raw PII** (the email or phone as provided). Use the `id` field to reference this identity in subsequent operations.

### Error Responses

All errors return a JSON body with this structure:

```json
{
  "error": {
    "code": "string_code",
    "message": "human-readable description",
    "details": [ ... ]  // optional, for validation errors
  }
}
```

| Status | Error code              | Cause                                                |
|--------|-------------------------|------------------------------------------------------|
| 400    | `invalid_json`          | Request body is not valid JSON                       |
| 400    | `invalid_tenant`        | `X-Tenant-Id` header is missing or not a valid UUID  |
| 400    | `validation_failed`     | One or more body fields failed validation. See `details`. |
| 404    | `tenant_not_found`      | The tenant UUID does not exist                       |
| 413    | `payload_too_large`     | Request body exceeds 100 KB                          |
| 415    | `unsupported_media_type`| `Content-Type` is not `application/json`             |
| 500    | `internal_error`        | Unexpected server error. Should not occur in normal operation. |
| 503    | `service_unavailable`   | Database is temporarily unavailable. Retry the request. |

**Validation error details:**

For 400 `validation_failed` responses, the `details` array contains one or more entries:

```json
{
  "error": {
    "code": "validation_failed",
    "message": "request validation failed",
    "details": [
      {
        "field": "email",
        "code": "invalid_format",
        "message": "email must be a valid email address"
      }
    ]
  }
}
```

Common validation codes:

| Code                  | Meaning                                                       |
|-----------------------|---------------------------------------------------------------|
| `missing`             | Required field is absent                                      |
| `missing_identifier`  | Neither `email` nor `phone` was provided                      |
| `invalid_type`        | Field has the wrong type (e.g., a number where a string was expected) |
| `invalid_format`      | Field does not match the expected format                      |
| `invalid_characters`  | Field contains characters that are not allowed (e.g., null bytes) |
| `too_long`            | Field exceeds the maximum length                              |

---

## Behavior Notes

### Identity Resolution

Two requests with identifiers that produce the same hash will return the same identity:

- `jane@example.com` and `JANE@example.com` are treated as the same email (case-insensitive normalization)
- `(555) 123-4567` and `555-123-4567` and `5551234567` are treated as the same phone (formatting stripped)
- Leading and trailing whitespace is trimmed before hashing

### Tenant Isolation

Identities are scoped to a tenant. The same email used in two different tenants creates two separate identity records. This is intentional — consent given to one business does not transfer to another, even for the same human.

### Privacy Guarantees

- Raw PII is never stored in the database. Only HMAC-SHA256 hashes and sanitized display values are persisted.
- Raw PII never appears in API responses. Only sanitized display values (`j***@example.com`) and the identity UUID are returned.
- Hashes are tenant-scoped and use a per-deployment salt, so even a database breach would not expose customer PII directly.

### Idempotency

Calling this endpoint multiple times with the same inputs is safe. The response will contain the same identity `id` each time. The `created` flag indicates whether a new identity was created on that specific call.

This makes the endpoint safe to retry after network failures.

---

## Implementation References

- Hashing: `src/lib/hashing.js`
- Identity resolution: `src/lib/identity.js`
- Validation: `src/lib/validation.js`
- Route handler: `src/routes/identity.js`

For architectural context, see `THREADOS_BIBLE.md` (Decisions 1, 2, 4, 7, 18).
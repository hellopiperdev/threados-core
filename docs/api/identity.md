# Identity API

ThreadOS Core's identity API provides PII hashing and identity resolution. Verticals call these endpoints to convert customer PII into stable identity records without ever storing raw PII themselves.

**Base path:** `/api/v1/identity`

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

Core fetches the public key from the vertical's JWKS endpoint to verify signatures. Public keys can be rotated by adding new ones to the JWKS document; old keys remain available until rotated out.

### Required JWT Claims

Tokens must contain these claims:

| Claim | Type | Description |
|-------|------|-------------|
| `iss` | string | Vertical slug (must match a registered vertical) |
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
| `Authorization`  | yes      | `Bearer <jwt>` — see Authentication above              |

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

The tenant ID comes from the `sub` claim of the verified JWT, not from the request body.

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
| `identity.display_email` | string \| null | Sanitized email for display |
| `identity.display_phone` | string \| null | Sanitized phone for display |
| `identity.display_name`  | string \| null | The name as provided, if any |
| `identity.created`       | boolean | `true` if a new identity was created, `false` if existing |

The response **never contains raw PII**. Use the `id` field to reference this identity in subsequent operations.

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

#### Authentication errors (401 Unauthorized)

| Error code              | Cause                                                  |
|-------------------------|--------------------------------------------------------|
| `missing_auth`          | `Authorization` header is absent                       |
| `invalid_auth_format`   | `Authorization` is not in `Bearer <token>` format      |
| `token_malformed`       | Token structure is wrong, headers missing, etc.        |
| `unknown_issuer`        | `iss` claim does not match a registered vertical       |
| `unknown_key`           | `kid` in token header does not match any key in JWKS   |
| `invalid_signature`     | Signature verification failed                          |
| `token_expired`         | Token's `exp` is in the past (beyond skew tolerance)   |
| `invalid_claims`        | Required claims missing or invalid                     |

#### Request errors (400 / 413 / 415)

| Status | Error code              | Cause                                                |
|--------|-------------------------|------------------------------------------------------|
| 400    | `invalid_json`          | Request body is not valid JSON                       |
| 400    | `validation_failed`     | One or more body fields failed validation. See `details`. |
| 413    | `payload_too_large`     | Request body exceeds 100 KB                          |
| 415    | `unsupported_media_type`| `Content-Type` is not `application/json`             |

#### Resource errors (404)

| Status | Error code              | Cause                                                |
|--------|-------------------------|------------------------------------------------------|
| 404    | `tenant_not_found`      | The tenant UUID in `sub` does not exist              |

#### Server errors (503)

| Status | Error code              | Cause                                                |
|--------|-------------------------|------------------------------------------------------|
| 503    | `service_unavailable`   | Core cannot verify the request (e.g., JWKS endpoint unreachable) or database is temporarily unavailable. Retry the request. |

#### Validation error details

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
| `invalid_type`        | Field has the wrong type                                      |
| `invalid_format`      | Field does not match the expected format                      |
| `invalid_characters`  | Field contains characters that are not allowed                |
| `too_long`            | Field exceeds the maximum length                              |

---

## Behavior Notes

### Identity Resolution

Two requests with identifiers that produce the same hash will return the same identity:

- `jane@example.com` and `JANE@example.com` are treated as the same email
- `(555) 123-4567` and `555-123-4567` and `5551234567` are treated as the same phone
- Leading and trailing whitespace is trimmed before hashing

### Tenant Isolation

Identities are scoped to a tenant. The same email used in two different tenants creates two separate identity records. The tenant is identified by the `sub` claim of the JWT. A vertical cannot read or write to a tenant other than the one specified in its signed token.

### Privacy Guarantees

- Raw PII is never stored in the database. Only HMAC-SHA256 hashes and sanitized display values are persisted.
- Raw PII never appears in API responses. Only sanitized display values and the identity UUID are returned.
- Hashes are tenant-scoped and use a per-deployment salt.

### Idempotency

Calling this endpoint multiple times with the same inputs is safe. The response will contain the same identity `id` each time. The `created` flag indicates whether a new identity was created on that specific call.

### Token Reuse Within Lifetime

The same JWT can be used for multiple requests until it expires. Tokens are short-lived (1-hour default, 24-hour maximum) and replay is an accepted property within that window. Generate fresh tokens per call or per batch of calls.

---

## Well-Known Endpoints

### GET /.well-known/jwks.json

Returns Core's own JWKS document. Future use: services that need to verify signatures Core itself produces.

Response (200):

```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "<base64url public key>",
      "kid": "<key id>",
      "alg": "EdDSA",
      "use": "sig"
    }
  ]
}
```

---

## Implementation References

- Hashing: `src/lib/hashing.js`
- Identity resolution: `src/lib/identity.js`
- Validation: `src/lib/validation.js`
- JWT signing and verification: `src/lib/jwt.js`
- JWKS handling: `src/lib/jwks.js`
- Auth middleware: `src/middleware/auth.js`
- Route handler: `src/routes/identity.js`

For architectural context, see `THREADOS_BIBLE.md` (Decisions 1, 2, 4, 7, 18).

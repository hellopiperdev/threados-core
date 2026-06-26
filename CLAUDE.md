# CLAUDE.md

This file orients Claude Code for work in the ThreadOS Core repository. Read it first in any new session.

For *why* anything is the way it is, see `THREADOS_BIBLE.md` in the repo root. That document is the authoritative source for all architectural decisions. Code comments cite Bible decisions by number; respect those.

---

## What This Is

ThreadOS is a privacy-first growth operating system with a modular architecture.

- **ThreadOS Core** (this repository) is the vertical-agnostic trust layer. It handles identity, consent, events, loyalty, and audit. It knows nothing about specific verticals.
- **Vertical modules** (ThreadOS Auto, eventually Hospitality, Retail, etc.) plug into Core. They handle industry-specific integrations and workflows.

Core is built before any vertical. Verticals call Core via signed HTTP requests.

The durable moat is regulatory and integration infrastructure — TCF 2.2 consent, hashed PII, identity resolution, audit. AI advancement is an accelerant, not a threat. Build for the privacy-first world that's arriving, not the surveillance world that's leaving.

---

## Stack

- **Language:** Node.js 18+
- **Web:** Express 4
- **Database:** PostgreSQL 15, accessed via `pg` (no ORM)
- **Crypto:** Node's built-in `crypto` module (no third-party JWT libraries — we wrote our own minimal Ed25519 implementation)
- **Dev environment:** GitHub Codespaces
- **Production target:** GCP Cloud Run + Cloud SQL + Secret Manager (deployment is end of Phase B)

No additional dependencies unless there's a strong reason. Every dependency is a security and maintenance surface.

---

## Repository Layout

```
threados-core/
├── THREADOS_BIBLE.md            authoritative architectural decisions
├── CLAUDE.md                    this file
├── db/
│   ├── schema.sql               base schema, idempotent
│   ├── migrations.sql           incremental schema changes
│   └── migrate.js               runs schema then migrations
├── docs/
│   └── api/                     API documentation
├── keys/                        Ed25519 dev keypairs (gitignored)
├── scripts/
│   └── generate-keys.js         Ed25519 keypair generator
├── src/
│   ├── index.js                 server entry point
│   ├── server.js                Express app construction
│   ├── lib/
│   │   ├── secrets.js           centralized secret access (the swap point for Secret Manager)
│   │   ├── db.js                connection pool + query helpers
│   │   ├── hashing.js           HMAC-SHA256 PII hashing
│   │   ├── identity.js          identity resolution business logic
│   │   ├── validation.js        request validation primitives
│   │   ├── jwt.js               Ed25519 JWT signing and verification
│   │   └── jwks.js              JWKS endpoint and fetching/caching
│   ├── middleware/
│   │   └── auth.js              requireSignedRequest middleware
│   └── routes/
│       ├── identity.js          POST /api/v1/identity/hash
│       └── wellKnown.js         GET /.well-known/jwks.json
└── tests/
    ├── helpers/
    │   └── auth.js              shared scaffolding for tests needing signed JWTs
    ├── lib/                     unit-style tests for src/lib modules
    ├── middleware/              middleware tests
    ├── routes/                  HTTP integration tests
    └── scripts/                 tests for tooling scripts
```

---

## Core Conventions

These are non-negotiable and should be preserved in any new code.

### Bible Citation In Code

Every file that implements a Bible-governed decision starts with a comment block citing the decision number. Example:

```javascript
// Bible references:
//   Decision 7: Opinionated gatekeeper - reject bad input with actionable errors
//   Decision 18: Service-to-service authentication
```

When adding new functionality, find the relevant Bible decision and cite it.

### The Gatekeeper Principle (Bible Decision 7)

Core is strict by default. Reject malformed input with structured, actionable error responses. Never silently coerce, never silently ignore unknown fields *that matter*, always return a clear error code and message. The error format:

```json
{
  "error": {
    "code": "machine_readable_code",
    "message": "human-readable description",
    "details": [ ... optional, for validation errors ... ]
  }
}
```

### Tenant Scoping (Bible Decision 4)

Every Core operation is scoped to a tenant. The tenant ID comes from the *verified* JWT `sub` claim, never from a request body or untrusted header. Tenant isolation is structural: identities in tenant A and tenant B are separate even if they represent the same human.

### Privacy by Architecture (Bible Decision 1, 10)

- Raw PII is never stored. Only HMAC-SHA256 hashes and sanitized display values.
- Raw PII never appears in API responses. Sanitized display values only (`j***@example.com`).
- PII never flows through event properties. Use the identity API for PII.

### Secrets Through `src/lib/secrets.js`

The rest of the codebase never reads `process.env.*` for sensitive values. All secret access goes through `secrets.js`. When we migrate to Secret Manager, only that one file changes. Keep this invariant.

### Synchronous Persistence For MVP

Operations return a 2xx only after data is durably persisted. No async-write-ahead patterns until we have specific reason and a Pub/Sub pipeline to support them. This is a *durable* choice for now, not deferred complexity.

### Critical Path vs Background Path (Bible Decision 17)

When designing new features, decide whether work is on the critical path (must complete before HTTP response) or background (can be async). Default to critical path; move to background only when justified.

---

## Authentication Model

All API requests require an Ed25519-signed JWT in the `Authorization: Bearer <token>` header.

- Verticals are registered in `registered_verticals` with a slug and JWKS URL
- Core fetches public keys from the vertical's JWKS endpoint (cached, default 1-hour TTL)
- JWT claims: `iss` (vertical slug), `sub` (tenant UUID), `iat`, `exp` required. Extra claims allowed and ignored.
- Algorithm pinned to EdDSA. Never accept alg=none, HS256, RS256, etc.
- Clock skew tolerance: 30 seconds both directions
- Maximum token lifetime: 24 hours

For full details, see `docs/api/identity.md`.

Dev keys live in `keys/` (gitignored). The `threados-core` keypair is for Core's own signing; the `test-vertical` keypair is for development and testing.

---

## Testing Discipline

The codebase has 291 tests across nine test files as of end of Step 5. **Every new feature adds tests.** Two kinds matter:

1. **Unit-style tests** in `tests/lib/` and `tests/middleware/` for module behavior
2. **HTTP integration tests** in `tests/routes/` for endpoint behavior including robustness scenarios

All tests use a minimal custom runner (no Jest/Mocha). The runner produces colored output and exits non-zero on failure. Pattern: `console.log` test name with check/cross, summary at end, `process.exit(1)` on any failure.

When adding test files, also:
1. Add a `test:<name>` script to `package.json`
2. Add the new test file to the main `test` chain in `package.json`

Both updates must happen together. The `test` chain is the source of truth for what runs in CI eventually.

Run tests with `npm test` (all) or `npm run test:<name>` (one file).

Manual exploration matters too. Don't only write isolated unit tests — for HTTP endpoints, run them against curl, send adversarial input, see what happens. This is how we found seven robustness issues in Step 4.

---

## Database Conventions

- Schema lives in `db/schema.sql` with all CREATE statements using `IF NOT EXISTS`
- Incremental changes go in `db/migrations.sql` and are tracked in the `schema_migrations` table
- Migration entries should be idempotent (use `ON CONFLICT DO NOTHING`)
- Tenant ID columns are always UUIDs, never serial integers
- Use `JSONB` for flexible-schema fields (e.g., event `properties`)
- Use `TIMESTAMP WITH TIME ZONE` (`TIMESTAMPTZ`), never naked `TIMESTAMP`
- All queries are parameterized through `$1`, `$2`, etc. — never string-concatenated
- All multi-statement operations use `withTransaction()` from `src/lib/db.js`

The connection pool is configured in `db.js` and gets its config from `secrets.js`. Don't bypass.

---

## Where We Are

```
Phase A: COMPLETE (Steps 1-4)
Phase B in progress:
  [✓] Step 5: JWT authentication (5 sessions + prerequisite, complete)
  [ ] Step 6: Event capture API (next)
  [ ] Step 7: Consent management
  [ ] Step 8: Audit logging pipeline
  [ ] Step 9: Loyalty wallet
  [ ] Step 10: Production deployment to GCP
```

Total tests passing: 291. Latest commit on `main` at time of writing: `7955e5b`.

The Step 6 design is settled (event capture endpoint with batch support, reject-all on validation failure, sync persistence, regex-based PII detection, identity/session/device linkage, idempotency via client-provided event_id). Sessions will be planned in the chat interface and executed here.

---

## Outstanding TODOs

Real tracked technical debt lives in ClickUp under "Piper Consulting Co → ThreadOS → Core — Technical Follow-ups," managed by Luna (Nate's Claude-based chief of staff). Don't try to track these in code comments; they rot. Code comments can flag *where* a TODO applies, but the master list is in ClickUp.

Categories of deferred work that affect Step 6+:

- **Consent enforcement in event capture** — Bible Decision 15. Wire in when consent API exists in Step 7.
- **Field-level event property schema validation** — Bible Decision 8. Currently accept properties as a typed JSONB blob without per-schema validation.
- **Anonymous event holding pattern** — Bible Decision 21. Dual-track 30-day individual + permanent aggregate. Designed but not yet implemented.
- **Row Level Security policies in PostgreSQL** — defense in depth on top of application-level tenant filtering. Before production.
- **Async event ingestion via Pub/Sub** — Bible Decision 17. When sync persistence shows scaling pain.
- **Strict unknown-field rejection in API requests** — currently silently ignored. Before MVP 1.
- **Email canonicalization decision (plus-tag handling)** — currently treats variants as distinct. Before MVP 1.
- **PII salt and DB credentials to Secret Manager** — folded into deployment work (Step 10).
- **Identity merging logic** — when one new request matches identity A by email AND identity B by phone. Before MVP 1.
- **Structured logging library** — before production.
- **Test framework migration / schema library** (Joi/Zod) — when endpoint count hits ~10-15.

If you propose deferring something, flag it explicitly. Distinguish *durable choice* ("X is correct, still correct at 100x scale") from *deferred complexity* ("X works now, will need Y when condition Z"). Only the second category is a TODO.

---

## Working Style

This project pacing has been deliberate: design conversations first, then execution, with verification at every step. Architecture discussions happen in the Claude.ai chat interface; execution happens here in Claude Code.

When working in Claude Code on this repo:

- Read `THREADOS_BIBLE.md` and the existing implementation before proposing changes
- For new files, match the structural conventions of similar existing files (comment headers with Bible citations, the test runner pattern, the error response shape, etc.)
- After any change, run the relevant tests. After significant changes, run the full suite (`npm test`)
- Don't make commits without confirming all tests pass
- For commit messages, follow the multi-paragraph format used in recent commits: short subject line, then a body explaining what changed and why
- If a design decision arises mid-execution that wasn't pre-decided, surface it rather than picking silently

The project has a strong commit cadence — every session ends with a clean commit. Don't leave work-in-progress sitting uncommitted across sessions.

---

## What To Cite, What Not To Re-Discover

Things to consult before proposing or building:

- `THREADOS_BIBLE.md` for *why* of any architectural choice
- This file (`CLAUDE.md`) for repo conventions
- `docs/api/identity.md` as the reference for API response/error shapes
- Existing files in the relevant directory for structural patterns

Things you don't need to re-derive:
- The JWT signing/verification protocol (use `src/lib/jwt.js`)
- The hashing strategy (use `src/lib/hashing.js`)
- The validation primitive patterns (use `src/lib/validation.js`)
- The DB query patterns (use `src/lib/db.js`)
- The auth middleware (use `src/middleware/auth.js`)

Building on the existing primitives is faster and safer than reinventing them.

---

## Contact And Process

Nate is the solo founder/developer. Luna is his Claude-based chief of staff managing ClickUp tasks. Architecture decisions get made by Nate (often with Claude in chat acting as technical advisor). Luna tracks the deferred work and surfaces it at appropriate milestone gates.

When in doubt, ask in the chat interface rather than guessing in code. The pattern that has worked: design first, build second, verify third. Don't skip the design step.

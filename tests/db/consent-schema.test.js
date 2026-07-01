// ============================================================================
// ThreadOS Core - Consent Schema Tests (Step 7 Session 1)
// ============================================================================
//
// Verifies the consent data model created by migration 005: the append-only
// bitemporal consent_records table and the current_consent projection.
//
// These are SCHEMA tests: they exercise the database's own constraints
// (CHECKs, foreign keys, NOT NULLs, primary keys, uniqueness, triggers) by
// attempting inserts that must succeed or fail. Application-level validation
// (Session 2) is a separate layer; here we prove the schema itself rejects
// bad data even if application code is bypassed (defense in depth).
//
// Tests create a temporary test tenant and identity, and clean everything up
// at the end (ON DELETE CASCADE removes consent rows).
//
// Bible references:
//   Decision 7:  Opinionated gatekeeper - controlled vocabularies enforced at
//                the schema level; case variants rejected, never coerced
//   Decision 13: Multi-dimensional consent - the five dimension columns
//   Decision 14: Compliance postures - consent_basis per-record values
//   Decision 15: Write-time enforcement - current_consent projection shape
//
// Usage:
//   node tests/db/consent-schema.test.js
// ============================================================================

require('dotenv').config();

const crypto = require('crypto');
const { query, shutdown } = require('../../src/lib/db');

// ----------------------------------------------------------------------------
// Test runner state
// ----------------------------------------------------------------------------

let passed = 0;
let failed = 0;

const colors = {
    reset: '\x1b[0m',
    bold: '\x1b[1m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    red: '\x1b[31m',
    blue: '\x1b[34m',
    gray: '\x1b[90m',
};

function section(name) {
    console.log(`\n${colors.bold}${colors.blue}━━ ${name} ━━${colors.reset}`);
}

function test(name, actual, expected) {
    const matches = JSON.stringify(actual) === JSON.stringify(expected);
    if (matches) {
        passed++;
        console.log(`${colors.green}✓${colors.reset} ${name}`);
    } else {
        failed++;
        console.log(`${colors.red}✗${colors.reset} ${name}`);
        console.log(`  ${colors.gray}expected:${colors.reset} ${JSON.stringify(expected)}`);
        console.log(`  ${colors.gray}actual:  ${colors.reset} ${JSON.stringify(actual)}`);
    }
}

function testThat(name, condition, hint) {
    if (condition) {
        passed++;
        console.log(`${colors.green}✓${colors.reset} ${name}`);
    } else {
        failed++;
        console.log(`${colors.red}✗${colors.reset} ${name}`);
        if (hint) console.log(`  ${colors.gray}${hint}${colors.reset}`);
    }
}

// ----------------------------------------------------------------------------
// PostgreSQL error codes we assert against
// ----------------------------------------------------------------------------

const PG = {
    NOT_NULL_VIOLATION: '23502',
    FK_VIOLATION: '23503',
    UNIQUE_VIOLATION: '23505',
    CHECK_VIOLATION: '23514',
};

// ----------------------------------------------------------------------------
// Fixtures
// ----------------------------------------------------------------------------

const TEST_TENANT_SLUG = '_test_tenant_consent_schema';
let tenantId = null;
let identityId = null;

// A fully-valid consent_records row, overridable per test.
function makeRecord(overrides = {}) {
    return {
        tenant_id: tenantId,
        identity_id: identityId,
        purpose: 'marketing',
        vendor: 'mailchimp',
        channel: 'email',
        data_category: 'behavioral',
        jurisdiction: 'US-CA',
        state: 'granted',
        consent_basis: 'active_consent',
        captured_via: 'web_form',
        capture_context: 'newsletter signup form, homepage footer',
        reason: 'customer checked the marketing opt-in box',
        effective_from: '2026-06-01T00:00:00.000Z',
        effective_until: null,
        ...overrides,
    };
}

// Attempt an insert into consent_records; return { ok, code, record_id }.
// `code` is the PostgreSQL SQLSTATE on failure, letting tests assert not just
// that an insert failed, but that it failed for the expected reason.
async function insertRecord(overrides = {}) {
    const r = makeRecord(overrides);
    try {
        const res = await query(
            `INSERT INTO consent_records (
                tenant_id, identity_id, purpose, vendor, channel, data_category,
                jurisdiction, state, consent_basis, captured_via,
                capture_context, reason, effective_from, effective_until
             )
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
             RETURNING record_id`,
            [
                r.tenant_id, r.identity_id, r.purpose, r.vendor, r.channel,
                r.data_category, r.jurisdiction, r.state, r.consent_basis,
                r.captured_via, r.capture_context, r.reason,
                r.effective_from, r.effective_until,
            ]
        );
        return { ok: true, record_id: res.rows[0].record_id };
    } catch (err) {
        return { ok: false, code: err.code };
    }
}

// Attempt an insert into current_consent; return { ok, code }.
// source_record_id must reference a real consent_records row, so callers
// usually insert a history row first and pass its record_id.
async function insertCurrent(sourceRecordId, overrides = {}) {
    const r = makeRecord(overrides);
    try {
        await query(
            `INSERT INTO current_consent (
                tenant_id, identity_id, purpose, vendor, channel, data_category,
                jurisdiction, state, consent_basis, effective_from, source_record_id
             )
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
            [
                r.tenant_id, r.identity_id, r.purpose, r.vendor, r.channel,
                r.data_category, r.jurisdiction, r.state, r.consent_basis,
                r.effective_from, sourceRecordId,
            ]
        );
        return { ok: true };
    } catch (err) {
        return { ok: false, code: err.code };
    }
}

// Fetch { column_name: { data_type, is_nullable, character_maximum_length } }
// for a table from information_schema.
async function getColumns(tableName) {
    const res = await query(
        `SELECT column_name, data_type, is_nullable, character_maximum_length
         FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = $1`,
        [tableName]
    );
    const cols = {};
    for (const row of res.rows) {
        cols[row.column_name] = {
            type: row.data_type,
            nullable: row.is_nullable === 'YES',
            maxLength: row.character_maximum_length,
        };
    }
    return cols;
}

// Fetch the ordered primary key column list for a table.
async function getPrimaryKey(tableName) {
    const res = await query(
        `SELECT kcu.column_name
         FROM information_schema.table_constraints tc
         JOIN information_schema.key_column_usage kcu
           ON tc.constraint_name = kcu.constraint_name
          AND tc.table_schema = kcu.table_schema
         WHERE tc.table_schema = 'public'
           AND tc.table_name = $1
           AND tc.constraint_type = 'PRIMARY KEY'
         ORDER BY kcu.ordinal_position`,
        [tableName]
    );
    return res.rows.map(r => r.column_name);
}

async function setup() {
    await query(`DELETE FROM tenants WHERE slug = $1`, [TEST_TENANT_SLUG]);

    const t = await query(
        `INSERT INTO tenants (slug, display_name, vertical_module)
         VALUES ($1, 'Consent Schema Test Tenant', 'test') RETURNING id`,
        [TEST_TENANT_SLUG]
    );
    tenantId = t.rows[0].id;

    const idn = await query(
        `INSERT INTO identities (tenant_id, email_hash, resolution_key, match_source)
         VALUES ($1, $2, $3, 'deterministic') RETURNING id`,
        [tenantId, crypto.randomBytes(32).toString('hex'), crypto.randomBytes(32).toString('hex')]
    );
    identityId = idn.rows[0].id;
}

async function teardown() {
    await query(`DELETE FROM tenants WHERE slug = $1`, [TEST_TENANT_SLUG]);
    await shutdown();
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

async function runTests() {
    console.log(`${colors.bold}ThreadOS Core - Consent Schema Tests${colors.reset}`);

    try {
        section('Setup');
        await setup();
        console.log(`${colors.green}✓${colors.reset} Test tenant: ${tenantId}`);
        console.log(`${colors.green}✓${colors.reset} Test identity: ${identityId}`);

        // --------------------------------------------------------------------
        section('Table existence and column shapes');
        // --------------------------------------------------------------------

        const cr = await getColumns('consent_records');
        const cc = await getColumns('current_consent');

        testThat('consent_records table exists', Object.keys(cr).length > 0);
        testThat('current_consent table exists', Object.keys(cc).length > 0);

        test('consent_records has exactly the designed columns',
            Object.keys(cr).sort(),
            ['capture_context', 'captured_via', 'channel', 'consent_basis',
             'data_category', 'effective_from', 'effective_until', 'identity_id',
             'jurisdiction', 'purpose', 'reason', 'record_id', 'recorded_at',
             'state', 'tenant_id', 'vendor'].sort());

        test('current_consent has exactly the designed columns',
            Object.keys(cc).sort(),
            ['channel', 'consent_basis', 'data_category', 'effective_from',
             'effective_until', // added by migration 007 (Session 5, HIGH-1)
             'identity_id', 'jurisdiction', 'purpose', 'source_record_id',
             'state', 'tenant_id', 'updated_at', 'vendor'].sort());

        // The legacy placeholder shape must be gone.
        testThat('legacy granted column is gone', cr.granted === undefined);
        testThat('legacy tcf_string column is gone', cr.tcf_string === undefined);
        testThat('legacy superseded_by column is gone', cr.superseded_by === undefined);

        // Types and nullability on the columns that carry the design.
        test('record_id is uuid', cr.record_id.type, 'uuid');
        test('vendor is varchar(200)', [cr.vendor.type, cr.vendor.maxLength], ['character varying', 200]);
        test('purpose is varchar(30)', [cr.purpose.type, cr.purpose.maxLength], ['character varying', 30]);
        test('channel is varchar(20)', [cr.channel.type, cr.channel.maxLength], ['character varying', 20]);
        test('jurisdiction is varchar(10)', [cr.jurisdiction.type, cr.jurisdiction.maxLength], ['character varying', 10]);
        test('capture_context is text', cr.capture_context.type, 'text');
        test('reason is text', cr.reason.type, 'text');
        test('effective_from is timestamptz', cr.effective_from.type, 'timestamp with time zone');
        test('effective_until is timestamptz', cr.effective_until.type, 'timestamp with time zone');
        test('recorded_at is timestamptz', cr.recorded_at.type, 'timestamp with time zone');
        test('source_record_id is uuid', cc.source_record_id.type, 'uuid');
        test('updated_at is timestamptz', cc.updated_at.type, 'timestamp with time zone');

        testThat('effective_until is the only nullable consent_records column',
            Object.entries(cr).every(([name, col]) =>
                name === 'effective_until' ? col.nullable : !col.nullable),
            'every column except effective_until must be NOT NULL');

        // effective_until became the one nullable projection column in
        // migration 007 (NULL = open-ended window), mirroring consent_records.
        testThat('effective_until is the only nullable current_consent column',
            Object.entries(cc).every(([name, col]) =>
                name === 'effective_until' ? col.nullable : !col.nullable),
            'every column except effective_until must be NOT NULL');
        test('current_consent effective_until is timestamptz',
            cc.effective_until.type, 'timestamp with time zone');

        // --------------------------------------------------------------------
        section('Primary key structure');
        // --------------------------------------------------------------------

        test('consent_records PK is record_id',
            await getPrimaryKey('consent_records'), ['record_id']);

        test('current_consent PK is the seven-dimension tuple',
            await getPrimaryKey('current_consent'),
            ['tenant_id', 'identity_id', 'purpose', 'vendor', 'channel',
             'data_category', 'jurisdiction']);

        // --------------------------------------------------------------------
        section('A fully-valid record inserts');
        // --------------------------------------------------------------------

        const valid = await insertRecord();
        testThat('valid consent record accepted', valid.ok, `code: ${valid.code}`);

        const stored = await query(
            `SELECT recorded_at, effective_until FROM consent_records WHERE record_id = $1`,
            [valid.record_id]
        );
        testThat('recorded_at defaulted to a timestamp',
            stored.rows[0].recorded_at instanceof Date);
        test('effective_until stored as NULL (currently in effect)',
            stored.rows[0].effective_until, null);

        // --------------------------------------------------------------------
        section('Controlled vocabularies (Decision 7: exact lowercase only)');
        // --------------------------------------------------------------------

        // Each entry: [column, one valid value, invalid values that must be
        // rejected - case variants, misspellings, out-of-vocabulary values].
        const vocabCases = [
            ['purpose', 'fraud_prevention',
                ['Marketing', 'MARKETING', 'marketting', 'advertising', 'sales']],
            ['channel', 'in_app',
                ['Email', 'EMAIL', 'e-mail', 'phone', 'web', 'fax']],
            ['data_category', 'health',
                ['PII', 'Pii', 'standard', 'biometric', 'behavioural']],
            ['state', 'withdrawn',
                ['Granted', 'GRANTED', 'granted ', 'revoked', 'pending', 'maybe']],
            ['consent_basis', 'undocumented',
                ['Active_Consent', 'ACTIVE_CONSENT', 'contractual', 'withdrawn', 'implied']],
            ['captured_via', 'paper_form',
                ['Web_Form', 'WEB_FORM', 'phone_call', 'import', 'sms']],
        ];

        for (const [column, validValue, invalidValues] of vocabCases) {
            const okRes = await insertRecord({ [column]: validValue });
            testThat(`${column} = '${validValue}' accepted`, okRes.ok, `code: ${okRes.code}`);

            for (const bad of invalidValues) {
                const badRes = await insertRecord({ [column]: bad });
                testThat(`${column} = '${bad}' rejected by CHECK`,
                    !badRes.ok && badRes.code === PG.CHECK_VIOLATION,
                    `expected 23514, got ok=${badRes.ok} code=${badRes.code}`);
            }
        }

        // The legacy vocabulary's 'contractual_necessity' (22 chars) is longer
        // than the new VARCHAR(20) column, so it's rejected by the length bound
        // (22001) before the CHECK is even consulted - rejected either way.
        const legacyBasis = await insertRecord({ consent_basis: 'contractual_necessity' });
        testThat("legacy consent_basis 'contractual_necessity' rejected (length bound)",
            !legacyBasis.ok && legacyBasis.code === '22001',
            `expected 22001, got ok=${legacyBasis.ok} code=${legacyBasis.code}`);

        // Every valid vocabulary value must be insertable (full coverage, so a
        // typo in the schema's CHECK list can't hide behind spot checks).
        const fullVocab = {
            purpose: ['marketing', 'personalization', 'analytics',
                      'service_operations', 'legal_compliance', 'fraud_prevention'],
            channel: ['email', 'sms', 'voice', 'push', 'mail', 'in_app'],
            data_category: ['behavioral', 'pii', 'location', 'financial', 'health'],
            state: ['granted', 'denied', 'withdrawn'],
            consent_basis: ['active_consent', 'documented_opt_in', 'legitimate_interest',
                            'contract', 'legal_obligation', 'undocumented'],
            captured_via: ['web_form', 'email_response', 'phone', 'in_person',
                           'imported', 'api_direct', 'paper_form'],
        };
        for (const [column, values] of Object.entries(fullVocab)) {
            let allOk = true;
            for (const v of values) {
                const res = await insertRecord({ [column]: v });
                if (!res.ok) allOk = false;
            }
            testThat(`every valid ${column} value accepted (${values.length} values)`, allOk);
        }

        // --------------------------------------------------------------------
        section('Length bounds on free text');
        // --------------------------------------------------------------------

        const reason2000 = await insertRecord({ reason: 'r'.repeat(2000) });
        testThat('reason at 2000 chars accepted', reason2000.ok, `code: ${reason2000.code}`);

        const reason2001 = await insertRecord({ reason: 'r'.repeat(2001) });
        testThat('reason at 2001 chars rejected by CHECK',
            !reason2001.ok && reason2001.code === PG.CHECK_VIOLATION,
            `expected 23514, got ok=${reason2001.ok} code=${reason2001.code}`);

        const ctx2000 = await insertRecord({ capture_context: 'c'.repeat(2000) });
        testThat('capture_context at 2000 chars accepted', ctx2000.ok, `code: ${ctx2000.code}`);

        const ctx2001 = await insertRecord({ capture_context: 'c'.repeat(2001) });
        testThat('capture_context at 2001 chars rejected by CHECK',
            !ctx2001.ok && ctx2001.code === PG.CHECK_VIOLATION,
            `expected 23514, got ok=${ctx2001.ok} code=${ctx2001.code}`);

        const vendor200 = await insertRecord({ vendor: 'v'.repeat(200) });
        testThat('vendor at 200 chars accepted', vendor200.ok, `code: ${vendor200.code}`);

        // Over-length varchar raises 22001 (string_data_right_truncation), not
        // a CHECK violation - either way the row must not land.
        const vendor201 = await insertRecord({ vendor: 'v'.repeat(201) });
        testThat('vendor at 201 chars rejected', !vendor201.ok, `code: ${vendor201.code}`);

        // --------------------------------------------------------------------
        section('Temporal integrity');
        // --------------------------------------------------------------------

        const goodWindow = await insertRecord({
            effective_from: '2026-01-01T00:00:00.000Z',
            effective_until: '2026-12-31T00:00:00.000Z',
        });
        testThat('effective_until after effective_from accepted', goodWindow.ok,
            `code: ${goodWindow.code}`);

        const invertedWindow = await insertRecord({
            effective_from: '2026-12-31T00:00:00.000Z',
            effective_until: '2026-01-01T00:00:00.000Z',
        });
        testThat('effective_until before effective_from rejected',
            !invertedWindow.ok && invertedWindow.code === PG.CHECK_VIOLATION,
            `expected 23514, got ok=${invertedWindow.ok} code=${invertedWindow.code}`);

        const zeroWindow = await insertRecord({
            effective_from: '2026-06-01T00:00:00.000Z',
            effective_until: '2026-06-01T00:00:00.000Z',
        });
        testThat('effective_until equal to effective_from rejected (must be strictly after)',
            !zeroWindow.ok && zeroWindow.code === PG.CHECK_VIOLATION,
            `expected 23514, got ok=${zeroWindow.ok} code=${zeroWindow.code}`);

        // --------------------------------------------------------------------
        section('NOT NULL constraints');
        // --------------------------------------------------------------------

        const requiredFields = [
            'tenant_id', 'identity_id', 'purpose', 'vendor', 'channel',
            'data_category', 'jurisdiction', 'state', 'consent_basis',
            'captured_via', 'capture_context', 'reason', 'effective_from',
        ];
        for (const field of requiredFields) {
            const res = await insertRecord({ [field]: null });
            testThat(`consent_records.${field} = NULL rejected`,
                !res.ok && res.code === PG.NOT_NULL_VIOLATION,
                `expected 23502, got ok=${res.ok} code=${res.code}`);
        }

        // --------------------------------------------------------------------
        section('Foreign keys');
        // --------------------------------------------------------------------

        const ghostUuid = crypto.randomUUID();

        const badTenant = await insertRecord({ tenant_id: ghostUuid });
        testThat('consent_records with nonexistent tenant_id rejected',
            !badTenant.ok && badTenant.code === PG.FK_VIOLATION,
            `expected 23503, got ok=${badTenant.ok} code=${badTenant.code}`);

        const badIdentity = await insertRecord({ identity_id: ghostUuid });
        testThat('consent_records with nonexistent identity_id rejected',
            !badIdentity.ok && badIdentity.code === PG.FK_VIOLATION,
            `expected 23503, got ok=${badIdentity.ok} code=${badIdentity.code}`);

        const badSource = await insertCurrent(ghostUuid);
        testThat('current_consent with nonexistent source_record_id rejected',
            !badSource.ok && badSource.code === PG.FK_VIOLATION,
            `expected 23503, got ok=${badSource.ok} code=${badSource.code}`);

        // --------------------------------------------------------------------
        section('current_consent projection: uniqueness and vocabularies');
        // --------------------------------------------------------------------

        const src = await insertRecord({ vendor: 'projection_test_vendor' });
        testThat('source history row created', src.ok, `code: ${src.code}`);

        const first = await insertCurrent(src.record_id, { vendor: 'projection_test_vendor' });
        testThat('first projection row for a dimension tuple accepted', first.ok,
            `code: ${first.code}`);

        const dup = await insertCurrent(src.record_id, { vendor: 'projection_test_vendor' });
        testThat('second projection row for the SAME dimension tuple rejected',
            !dup.ok && dup.code === PG.UNIQUE_VIOLATION,
            `expected 23505, got ok=${dup.ok} code=${dup.code}`);

        const differentVendor = await insertCurrent(src.record_id, { vendor: 'projection_test_vendor_2' });
        testThat('projection row differing only by vendor accepted', differentVendor.ok,
            `code: ${differentVendor.code}`);

        const ccBadState = await insertCurrent(src.record_id,
            { vendor: 'projection_test_vendor_3', state: 'Granted' });
        testThat('current_consent state case variant rejected by CHECK',
            !ccBadState.ok && ccBadState.code === PG.CHECK_VIOLATION,
            `expected 23514, got ok=${ccBadState.ok} code=${ccBadState.code}`);

        const ccBadPurpose = await insertCurrent(src.record_id,
            { vendor: 'projection_test_vendor_4', purpose: 'advertising' });
        testThat('current_consent out-of-vocabulary purpose rejected by CHECK',
            !ccBadPurpose.ok && ccBadPurpose.code === PG.CHECK_VIOLATION,
            `expected 23514, got ok=${ccBadPurpose.ok} code=${ccBadPurpose.code}`);

        // --------------------------------------------------------------------
        section('current_consent updated_at trigger');
        // --------------------------------------------------------------------

        const before = await query(
            `SELECT updated_at FROM current_consent
             WHERE tenant_id = $1 AND identity_id = $2 AND vendor = 'projection_test_vendor'`,
            [tenantId, identityId]
        );
        // The trigger sets updated_at = CURRENT_TIMESTAMP, which is transaction
        // start time; a same-millisecond update could produce an equal value, so
        // wait a moment to make strict inequality meaningful.
        await new Promise(resolve => setTimeout(resolve, 25));
        await query(
            `UPDATE current_consent SET state = 'withdrawn'
             WHERE tenant_id = $1 AND identity_id = $2 AND vendor = 'projection_test_vendor'`,
            [tenantId, identityId]
        );
        const after = await query(
            `SELECT state, updated_at FROM current_consent
             WHERE tenant_id = $1 AND identity_id = $2 AND vendor = 'projection_test_vendor'`,
            [tenantId, identityId]
        );
        test('projection state updated', after.rows[0].state, 'withdrawn');
        testThat('updated_at advanced on UPDATE',
            after.rows[0].updated_at > before.rows[0].updated_at,
            `before=${before.rows[0].updated_at?.toISOString()} after=${after.rows[0].updated_at?.toISOString()}`);

        // --------------------------------------------------------------------
        section('Erasure cascade (Decision 6)');
        // --------------------------------------------------------------------

        // Deleting an identity must remove its consent history AND projection
        // rows in one cascade - this is the right-to-erasure path, and it's why
        // append-only is an application convention rather than a DELETE-blocking
        // trigger.
        const eraseIdn = await query(
            `INSERT INTO identities (tenant_id, email_hash, resolution_key, match_source)
             VALUES ($1, $2, $3, 'deterministic') RETURNING id`,
            [tenantId, crypto.randomBytes(32).toString('hex'), crypto.randomBytes(32).toString('hex')]
        );
        const eraseIdentityId = eraseIdn.rows[0].id;

        const eraseSrc = await insertRecord({ identity_id: eraseIdentityId });
        const eraseCur = await insertCurrent(eraseSrc.record_id, { identity_id: eraseIdentityId });
        testThat('erasure fixture rows created', eraseSrc.ok && eraseCur.ok);

        await query(`DELETE FROM identities WHERE id = $1`, [eraseIdentityId]);

        const orphanHistory = await query(
            `SELECT COUNT(*)::int AS n FROM consent_records WHERE identity_id = $1`,
            [eraseIdentityId]
        );
        const orphanCurrent = await query(
            `SELECT COUNT(*)::int AS n FROM current_consent WHERE identity_id = $1`,
            [eraseIdentityId]
        );
        test('identity deletion cascades to consent_records', orphanHistory.rows[0].n, 0);
        test('identity deletion cascades to current_consent', orphanCurrent.rows[0].n, 0);

        // --------------------------------------------------------------------
        section('Migration record');
        // --------------------------------------------------------------------

        const mig = await query(
            `SELECT version FROM schema_migrations WHERE version = '005_consent_data_model'`
        );
        test('migration 005 recorded in schema_migrations', mig.rows.length, 1);

    } finally {
        section('Teardown');
        try {
            await teardown();
            console.log(`${colors.green}✓${colors.reset} Cleaned up test tenant`);
        } catch (err) {
            console.log(`${colors.yellow}⚠${colors.reset} Teardown error: ${err.message}`);
        }
    }

    console.log(`\n${colors.bold}━━ Summary ━━${colors.reset}`);
    console.log(`${colors.green}Passed:${colors.reset} ${passed}`);
    if (failed > 0) {
        console.log(`${colors.red}Failed:${colors.reset} ${failed}`);
        process.exit(1);
    } else {
        console.log(`${colors.gray}No failures.${colors.reset}\n`);
        process.exit(0);
    }
}

runTests().catch(err => {
    console.error('Unexpected error in test runner:', err);
    process.exit(1);
});

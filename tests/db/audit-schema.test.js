// ============================================================================
// ThreadOS Core - Audit Log Schema Tests
// ============================================================================
//
// Validates the audit_log table against the settled Step 8 design: shape,
// vocabularies (with case-variant rejection), the bounded detail blob, the
// indexes - and the LOAD-BEARING no-foreign-key property: audit rows must
// survive erasure cascades. The survival test deletes a tenant (cascading
// its identities) and asserts the audit rows remain, UUIDs intact.
//
// Usage:
//   node tests/db/audit-schema.test.js
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

// Expect an insert to fail with a CHECK violation (23514).
async function expectCheckViolation(name, sql, params) {
    try {
        await query(sql, params);
        testThat(name, false, 'insert unexpectedly succeeded');
    } catch (err) {
        testThat(name, err.code === '23514', `expected 23514, got ${err.code}: ${err.message}`);
    }
}

const TEST_TENANT_SLUG = '_test_tenant_audit_schema';

function baseInsert(overrides = {}) {
    const row = {
        audit_action: 'consent_recorded',
        actor: '_test_vertical',
        tenant_id: crypto.randomUUID(),
        subject_identity_id: null,
        outcome: 'success',
        outcome_reason: null,
        detail: {},
        ...overrides,
    };
    return {
        sql: `INSERT INTO audit_log (audit_action, actor, tenant_id, subject_identity_id, outcome, outcome_reason, detail)
              VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING audit_id`,
        params: [row.audit_action, row.actor, row.tenant_id, row.subject_identity_id,
            row.outcome, row.outcome_reason, row.detail],
    };
}

async function runTests() {
    console.log(`${colors.bold}ThreadOS Core - Audit Log Schema Tests${colors.reset}`);

    const cleanupIds = [];

    try {
        // --------------------------------------------------------------------
        section('Table shape');
        // --------------------------------------------------------------------

        const cols = await query(
            `SELECT column_name, data_type, is_nullable
             FROM information_schema.columns
             WHERE table_schema = 'public' AND table_name = 'audit_log'
             ORDER BY column_name`);
        const byName = Object.fromEntries(cols.rows.map(c => [c.column_name, c]));

        test('audit_log has exactly the designed columns',
            Object.keys(byName).sort(),
            ['actor', 'audit_action', 'audit_id', 'detail', 'occurred_at',
             'outcome', 'outcome_reason', 'subject_identity_id', 'tenant_id'].sort());

        test('audit_id is uuid', byName.audit_id.data_type, 'uuid');
        test('tenant_id is uuid', byName.tenant_id.data_type, 'uuid');
        test('subject_identity_id is uuid', byName.subject_identity_id.data_type, 'uuid');
        test('detail is jsonb', byName.detail.data_type, 'jsonb');
        test('occurred_at is timestamptz', byName.occurred_at.data_type, 'timestamp with time zone');

        testThat('nullable columns are exactly subject_identity_id and outcome_reason',
            cols.rows.every(c =>
                ['subject_identity_id', 'outcome_reason'].includes(c.column_name)
                    ? c.is_nullable === 'YES' : c.is_nullable === 'NO'),
            JSON.stringify(cols.rows.map(c => `${c.column_name}:${c.is_nullable}`)));

        const pk = await query(
            `SELECT a.attname FROM pg_index i
             JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
             WHERE i.indrelid = 'audit_log'::regclass AND i.indisprimary`);
        test('primary key is audit_id', pk.rows.map(r => r.attname), ['audit_id']);

        // --------------------------------------------------------------------
        section('No foreign keys, no update trigger (append-only by design)');
        // --------------------------------------------------------------------

        const fks = await query(
            `SELECT conname FROM pg_constraint
             WHERE conrelid = 'audit_log'::regclass AND contype = 'f'`);
        test('audit_log has ZERO foreign keys (the load-bearing rule)',
            fks.rows.length, 0);

        const triggers = await query(
            `SELECT trigger_name FROM information_schema.triggers
             WHERE event_object_table = 'audit_log'`);
        test('audit_log has no triggers (rows are never updated)',
            triggers.rows.length, 0);

        // --------------------------------------------------------------------
        section('Vocabularies (with case-variant rejection)');
        // --------------------------------------------------------------------

        for (const action of ['consent_recorded', 'consent_read', 'capture_allowed',
            'capture_denied', 'capture_unavailable', 'backfill_evaluated', 'identity_hashed']) {
            const { sql, params } = baseInsert({
                audit_action: action,
                outcome: action === 'capture_denied' ? 'denied'
                    : action === 'capture_unavailable' ? 'unavailable' : 'success',
            });
            const r = await query(sql, params);
            cleanupIds.push(r.rows[0].audit_id);
            testThat(`action "${action}" accepted`, r.rows.length === 1);
        }

        {
            const { sql, params } = baseInsert({ audit_action: 'password_changed' });
            await expectCheckViolation('unknown action rejected', sql, params);
        }
        {
            const { sql, params } = baseInsert({ audit_action: 'Consent_Recorded' });
            await expectCheckViolation('case-variant action rejected', sql, params);
        }
        {
            const { sql, params } = baseInsert({ outcome: 'failed' });
            await expectCheckViolation('unknown outcome rejected', sql, params);
        }
        {
            const { sql, params } = baseInsert({ outcome: 'Success' });
            await expectCheckViolation('case-variant outcome rejected', sql, params);
        }

        // --------------------------------------------------------------------
        section('Detail size bound');
        // --------------------------------------------------------------------

        {
            const { sql, params } = baseInsert({ detail: { blob: 'x'.repeat(4100) } });
            await expectCheckViolation('detail over 4096 serialized chars rejected', sql, params);
        }
        {
            const { sql, params } = baseInsert({ detail: { blob: 'x'.repeat(4000) } });
            const r = await query(sql, params);
            cleanupIds.push(r.rows[0].audit_id);
            testThat('detail under the bound accepted', r.rows.length === 1);
        }

        // --------------------------------------------------------------------
        section('Indexes');
        // --------------------------------------------------------------------

        const idx = await query(
            `SELECT indexname FROM pg_indexes WHERE tablename = 'audit_log'`);
        const names = idx.rows.map(r => r.indexname);
        testThat('operator index (tenant, occurred_at DESC) exists',
            names.includes('audit_log_tenant_occurred'), JSON.stringify(names));
        testThat('per-identity index (tenant, subject, occurred_at DESC) exists',
            names.includes('audit_log_tenant_subject_occurred'), JSON.stringify(names));

        // --------------------------------------------------------------------
        section('THE LOAD-BEARING PROPERTY: audit rows survive erasure cascades');
        // --------------------------------------------------------------------

        await query(`DELETE FROM tenants WHERE slug = $1`, [TEST_TENANT_SLUG]);
        const t = await query(
            `INSERT INTO tenants (slug, display_name, vertical_module)
             VALUES ($1, 'Audit Schema Test Tenant', 'test') RETURNING id`,
            [TEST_TENANT_SLUG]);
        const tenantId = t.rows[0].id;

        const idn = await query(
            `INSERT INTO identities (tenant_id, email_hash, resolution_key, match_source)
             VALUES ($1, $2, $3, 'deterministic') RETURNING id`,
            [tenantId, crypto.randomBytes(32).toString('hex'), crypto.randomBytes(32).toString('hex')]);
        const identityId = idn.rows[0].id;

        const auditRow = await query(
            `INSERT INTO audit_log (audit_action, actor, tenant_id, subject_identity_id, outcome, detail)
             VALUES ('consent_recorded', '_test_vertical', $1, $2, 'success', '{"record_count": 1}')
             RETURNING audit_id`,
            [tenantId, identityId]);
        const auditId = auditRow.rows[0].audit_id;
        cleanupIds.push(auditId);

        // The erasure: delete the tenant, which cascades its identities (and
        // its consent, events, everything with an FK). The audit row must not
        // be touched.
        await query(`DELETE FROM tenants WHERE id = $1`, [tenantId]);

        const tenantGone = await query(`SELECT 1 FROM tenants WHERE id = $1`, [tenantId]);
        test('tenant is gone', tenantGone.rows.length, 0);
        const identityGone = await query(`SELECT 1 FROM identities WHERE id = $1`, [identityId]);
        test('identity cascaded away', identityGone.rows.length, 0);

        const survived = await query(
            `SELECT tenant_id, subject_identity_id, audit_action, outcome, detail
             FROM audit_log WHERE audit_id = $1`, [auditId]);
        test('the audit row SURVIVED the erasure cascade', survived.rows.length, 1);
        test('it still names the deleted tenant by UUID (opaque reference)',
            survived.rows[0].tenant_id, tenantId);
        test('it still names the deleted identity by UUID (opaque reference)',
            survived.rows[0].subject_identity_id, identityId);
        test('its content is intact', survived.rows[0].detail, { record_count: 1 });

    } catch (err) {
        failed++;
        console.error(`\n${colors.red}Test run aborted:${colors.reset}`, err);
    } finally {
        section('Teardown');
        try {
            if (cleanupIds.length > 0) {
                await query(`DELETE FROM audit_log WHERE audit_id = ANY($1)`, [cleanupIds]);
            }
            await query(`DELETE FROM tenants WHERE slug = $1`, [TEST_TENANT_SLUG]);
        } catch (err) {
            console.log(`${colors.yellow}⚠${colors.reset} Cleanup failed: ${err.message}`);
        }
        await shutdown();
        console.log(`${colors.green}✓${colors.reset} Cleaned up`);
    }

    console.log(`\n${colors.bold}━━ Summary ━━${colors.reset}`);
    console.log(`${colors.green}Passed:${colors.reset} ${passed}`);
    if (failed > 0) {
        console.log(`${colors.red}Failed:${colors.reset} ${failed}`);
        process.exit(1);
    } else {
        console.log(`${colors.gray}No failures.${colors.reset}`);
    }
}

runTests();

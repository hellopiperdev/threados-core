// ============================================================================
// ThreadOS Core - Identity Repository Tests
// ============================================================================
//
// Exercises src/lib/identity.js against a real PostgreSQL database.
//
// Tests create a temporary test tenant, run their operations, and clean up
// at the end. The tenant has a recognizable name so leftover data can be
// identified if cleanup ever fails.
//
// Usage:
//   node tests/lib/identity.test.js
// ============================================================================

require('dotenv').config();

const { query, shutdown } = require('../../src/lib/db');
const {
    findIdentityByHash,
    getIdentityById,
    createIdentity,
    resolveIdentity: resolveIdentityRaw,
} = require('../../src/lib/identity');

// Step 8: identity resolution carries an actor for the audit trail.
const resolveIdentity = (t, ids, actor = '_test_identity_lib') => resolveIdentityRaw(t, ids, actor);
const { hashPII, normalizePhone } = require('../../src/lib/hashing');

// ----------------------------------------------------------------------------
// Test runner state
// ----------------------------------------------------------------------------

let passed = 0;
let failed = 0;
const failures = [];

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
        failures.push({ name, actual, expected });
        console.log(`${colors.red}✗${colors.reset} ${name}`);
        console.log(`  ${colors.gray}expected:${colors.reset} ${JSON.stringify(expected)}`);
        console.log(`  ${colors.gray}actual:  ${colors.reset} ${JSON.stringify(actual)}`);
    }
}

function testThat(name, condition) {
    if (condition) {
        passed++;
        console.log(`${colors.green}✓${colors.reset} ${name}`);
    } else {
        failed++;
        failures.push({ name, actual: 'condition was false', expected: 'condition true' });
        console.log(`${colors.red}✗${colors.reset} ${name}`);
    }
}

async function testThrowsAsync(name, fn, expectedMessageFragment) {
    try {
        await fn();
        failed++;
        failures.push({ name, actual: 'no error thrown', expected: `error containing "${expectedMessageFragment}"` });
        console.log(`${colors.red}✗${colors.reset} ${name} (expected error, none thrown)`);
    } catch (err) {
        if (err.message.includes(expectedMessageFragment)) {
            passed++;
            console.log(`${colors.green}✓${colors.reset} ${name}`);
        } else {
            failed++;
            failures.push({ name, actual: err.message, expected: `error containing "${expectedMessageFragment}"` });
            console.log(`${colors.red}✗${colors.reset} ${name}`);
            console.log(`  ${colors.gray}expected error containing:${colors.reset} ${expectedMessageFragment}`);
            console.log(`  ${colors.gray}actual error:             ${colors.reset} ${err.message}`);
        }
    }
}

// ----------------------------------------------------------------------------
// Test fixtures and cleanup
// ----------------------------------------------------------------------------

const TEST_TENANT_SLUG = '_test_tenant_session_3';
let testTenantId = null;
let otherTestTenantId = null;

async function setupTestTenants() {
    // Clean up any leftover from previous failed runs
    await query(
        `DELETE FROM tenants WHERE slug IN ($1, $2)`,
        [TEST_TENANT_SLUG, TEST_TENANT_SLUG + '_other']
    );

    // Create primary test tenant
    const result1 = await query(
        `INSERT INTO tenants (slug, display_name, vertical_module)
         VALUES ($1, 'Session 3 Test Tenant', 'test')
         RETURNING id`,
        [TEST_TENANT_SLUG]
    );
    testTenantId = result1.rows[0].id;

    // Create a second tenant to verify tenant isolation
    const result2 = await query(
        `INSERT INTO tenants (slug, display_name, vertical_module)
         VALUES ($1, 'Session 3 Other Tenant', 'test')
         RETURNING id`,
        [TEST_TENANT_SLUG + '_other']
    );
    otherTestTenantId = result2.rows[0].id;
}

async function teardownTestTenants() {
    // audit_log has no FKs (by design) - clean test audit rows explicitly.
    await query(
        `DELETE FROM audit_log WHERE tenant_id IN (
            SELECT id FROM tenants WHERE slug IN ($1, $2))`,
        [TEST_TENANT_SLUG, TEST_TENANT_SLUG + '_other']
    );
    // ON DELETE CASCADE handles all the related identities
    await query(
        `DELETE FROM tenants WHERE slug IN ($1, $2)`,
        [TEST_TENANT_SLUG, TEST_TENANT_SLUG + '_other']
    );
}

// ----------------------------------------------------------------------------
// Main test execution
// ----------------------------------------------------------------------------

async function runTests() {
    console.log(`${colors.bold}ThreadOS Core - Identity Repository Tests${colors.reset}`);

    try {
        section('Setup');
        await setupTestTenants();
        console.log(`${colors.green}✓${colors.reset} Created test tenants`);
        console.log(`  ${colors.gray}primary: ${testTenantId}${colors.reset}`);
        console.log(`  ${colors.gray}other:   ${otherTestTenantId}${colors.reset}`);

        // --------------------------------------------------------------------
        // createIdentity
        // --------------------------------------------------------------------

        section('createIdentity');

        const emailHash1 = hashPII('alice@example.com');
        const phoneHash1 = hashPII(normalizePhone('555-111-1111'));

        const created = await createIdentity(testTenantId, {
            emailHash: emailHash1,
            phoneHash: phoneHash1,
            displayEmail: 'a****@example.com',
            displayPhone: '***-***-1111',
            displayName: 'Alice',
        });

        testThat('returns a row with an id', created.id && typeof created.id === 'string');
        test('tenant_id matches', created.tenant_id, testTenantId);
        test('email_hash matches', created.email_hash, emailHash1);
        test('phone_hash matches', created.phone_hash, phoneHash1);
        test('match_source is deterministic', created.match_source, 'deterministic');
        test('is_active defaults to true', created.is_active, true);
        testThat('has resolution_key', created.resolution_key && created.resolution_key.length === 64);

        await testThrowsAsync(
            'throws without tenantId',
            () => createIdentity(null, { emailHash: emailHash1 }),
            'tenantId is required'
        );

        await testThrowsAsync(
            'throws without any identifier',
            () => createIdentity(testTenantId, {}),
            'At least one of emailHash or phoneHash is required'
        );

        // --------------------------------------------------------------------
        // findIdentityByHash
        // --------------------------------------------------------------------

        section('findIdentityByHash');

        const foundByEmail = await findIdentityByHash(testTenantId, emailHash1, null);
        test('finds by email hash', foundByEmail && foundByEmail.id, created.id);

        const foundByPhone = await findIdentityByHash(testTenantId, null, phoneHash1);
        test('finds by phone hash', foundByPhone && foundByPhone.id, created.id);

        const foundByBoth = await findIdentityByHash(testTenantId, emailHash1, phoneHash1);
        test('finds by both hashes', foundByBoth && foundByBoth.id, created.id);

        const notFoundEmail = await findIdentityByHash(testTenantId, hashPII('nobody@example.com'), null);
        test('returns null when not found', notFoundEmail, null);

        // Tenant isolation: same hash in different tenant should NOT find
        const tenantIsolation = await findIdentityByHash(otherTestTenantId, emailHash1, null);
        test('respects tenant isolation', tenantIsolation, null);

        await testThrowsAsync(
            'throws without tenantId',
            () => findIdentityByHash(null, emailHash1, null),
            'tenantId is required'
        );

        await testThrowsAsync(
            'throws without any hash',
            () => findIdentityByHash(testTenantId, null, null),
            'At least one of emailHash or phoneHash is required'
        );

        // --------------------------------------------------------------------
        // getIdentityById
        // --------------------------------------------------------------------

        section('getIdentityById');

        const fetched = await getIdentityById(testTenantId, created.id);
        test('fetches by id', fetched && fetched.id, created.id);

        const notFoundById = await getIdentityById(
            testTenantId,
            '00000000-0000-0000-0000-000000000000'
        );
        test('returns null for unknown id', notFoundById, null);

        // Cross-tenant lookup should fail (returns null)
        const crossTenant = await getIdentityById(otherTestTenantId, created.id);
        test('respects tenant scoping', crossTenant, null);

        // --------------------------------------------------------------------
        // resolveIdentity - new identity creation
        // --------------------------------------------------------------------

        section('resolveIdentity: creates new identity');

        const result1 = await resolveIdentity(testTenantId, {
            email: 'bob@example.com',
            phone: '555-222-2222',
            name: 'Bob',
        });

        testThat('returns identity and created flag', result1.identity && typeof result1.created === 'boolean');
        test('marks as created', result1.created, true);
        testThat('identity has an id', result1.identity.id && typeof result1.identity.id === 'string');
        test('email_hash is set', result1.identity.email_hash, hashPII('bob@example.com'));
        test('phone_hash is set', result1.identity.phone_hash, hashPII(normalizePhone('555-222-2222')));
        test('display_email is sanitized', result1.identity.display_email, 'b**@example.com');
        test('display_phone is sanitized', result1.identity.display_phone, '***-***-2222');
        test('display_name is preserved', result1.identity.display_name, 'Bob');

        // --------------------------------------------------------------------
        // resolveIdentity - finds existing identity
        // --------------------------------------------------------------------

        section('resolveIdentity: finds existing identity');

        const result2 = await resolveIdentity(testTenantId, {
            email: 'bob@example.com',
            phone: '555-222-2222',
        });

        test('marks as not created', result2.created, false);
        test('returns same identity', result2.identity.id, result1.identity.id);

        // Resolving with case differences should find the same identity
        // (normalization happens during hashing)
        const result3 = await resolveIdentity(testTenantId, {
            email: 'BOB@example.com',
        });
        test('case-insensitive matching', result3.identity.id, result1.identity.id);
        test('case difference is not created', result3.created, false);

        // Resolving with different phone formatting should also match
        const result4 = await resolveIdentity(testTenantId, {
            phone: '(555) 222-2222',
        });
        test('phone format normalization works', result4.identity.id, result1.identity.id);

        // Audit integration (Step 8): every resolution above processed PII
        // and disclosed an identity, so each left an identity_hashed row.
        const hashAudits = await query(
            `SELECT actor, outcome, subject_identity_id, detail FROM audit_log
             WHERE tenant_id = $1 AND audit_action = 'identity_hashed'
             ORDER BY occurred_at, audit_id`,
            [testTenantId]);
        test('one identity_hashed audit row per resolution so far', hashAudits.rows.length, 4);
        test('audit actor is the caller', hashAudits.rows[0].actor, '_test_identity_lib');
        test('audit subject is the resolved identity',
            hashAudits.rows[0].subject_identity_id, result1.identity.id);
        test('first resolution audited as a creation',
            hashAudits.rows[0].detail.identity_created, true);
        test('second resolution audited as a match, not a creation',
            hashAudits.rows[1].detail.identity_created, false);
        test('detail names the PII fields provided - names only, never values',
            hashAudits.rows[0].detail.fields_provided, ['email', 'phone', 'name']);
        testThat('no audit detail ever contains raw PII',
            hashAudits.rows.every(r => !JSON.stringify(r.detail).includes('bob@example.com')));

        // --------------------------------------------------------------------
        // resolveIdentity - email-only or phone-only
        // --------------------------------------------------------------------

        section('resolveIdentity: partial identifiers');

        const emailOnly = await resolveIdentity(testTenantId, {
            email: 'charlie@example.com',
        });
        test('creates identity with email only', emailOnly.created, true);
        testThat('email_hash set, phone_hash null',
            emailOnly.identity.email_hash !== null && emailOnly.identity.phone_hash === null);

        const phoneOnly = await resolveIdentity(testTenantId, {
            phone: '555-333-3333',
        });
        test('creates identity with phone only', phoneOnly.created, true);
        testThat('phone_hash set, email_hash null',
            phoneOnly.identity.phone_hash !== null && phoneOnly.identity.email_hash === null);

        // --------------------------------------------------------------------
        // resolveIdentity - tenant isolation
        // --------------------------------------------------------------------

        section('resolveIdentity: tenant isolation');

        // Same email in a different tenant should create a new identity,
        // not return the one from the primary tenant
        const otherTenantBob = await resolveIdentity(otherTestTenantId, {
            email: 'bob@example.com',
        });
        test('creates new identity in different tenant', otherTenantBob.created, true);
        testThat('different identity id', otherTenantBob.identity.id !== result1.identity.id);
        test('same email_hash (deterministic)', otherTenantBob.identity.email_hash, result1.identity.email_hash);

        // --------------------------------------------------------------------
        // resolveIdentity - error cases
        // --------------------------------------------------------------------

        section('resolveIdentity: error cases');

        await testThrowsAsync(
            'throws without tenantId',
            () => resolveIdentity(null, { email: 'x@y.com' }),
            'tenantId is required'
        );

        await testThrowsAsync(
            'throws without any identifier',
            () => resolveIdentity(testTenantId, {}),
            'At least one of email or phone is required'
        );

        await testThrowsAsync(
            'throws with null identifiers object',
            () => resolveIdentity(testTenantId, null),
            'At least one of email or phone is required'
        );

    } finally {
        section('Teardown');
        try {
            await teardownTestTenants();
            console.log(`${colors.green}✓${colors.reset} Cleaned up test tenants`);
        } catch (err) {
            console.log(`${colors.yellow}⚠${colors.reset} Cleanup failed: ${err.message}`);
        }
        await shutdown();
    }

    // ------------------------------------------------------------------------
    // Summary
    // ------------------------------------------------------------------------

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
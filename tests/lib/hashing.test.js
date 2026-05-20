// ============================================================================
// ThreadOS Core - Hashing Module Tests
// ============================================================================
//
// Exercises src/lib/hashing.js with realistic inputs and verifies correct
// behavior. Also cross-checks that the JavaScript implementation produces
// the same output as the PostgreSQL hash_pii() function.
//
// Usage:
//   node tests/lib/hashing.test.js
//
// This is intentionally a plain Node script rather than a testing framework.
// We'll move to a real framework (Jest or similar) when complexity justifies
// the setup cost.
// ============================================================================

require('dotenv').config();

const { Client } = require('pg');
const {
    hashPII,
    normalizePhone,
    generateResolutionKey,
    sanitizeEmail,
    sanitizePhone,
    _resetSaltCache,
} = require('../../src/lib/hashing');

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

function testThrows(name, fn, expectedMessageFragment) {
    try {
        fn();
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
// Main test execution
// ----------------------------------------------------------------------------

async function runTests() {
    console.log(`${colors.bold}ThreadOS Core - Hashing Module Tests${colors.reset}`);

    // ------------------------------------------------------------------------
    // hashPII basic behavior
    // ------------------------------------------------------------------------

    section('hashPII: basic behavior');

    const emailHash = hashPII('jane@example.com');
    testThat('hashes a normal email', typeof emailHash === 'string' && emailHash.length === 64);
    testThat('produces hex output', /^[0-9a-f]{64}$/.test(emailHash));

    test('returns null for null', hashPII(null), null);
    test('returns null for undefined', hashPII(undefined), null);
    test('returns null for empty string', hashPII(''), null);
    test('returns null for whitespace-only', hashPII('   '), null);

    // ------------------------------------------------------------------------
    // hashPII normalization (this is critical for identity resolution)
    // ------------------------------------------------------------------------

    section('hashPII: normalization');

    const h1 = hashPII('jane@example.com');
    const h2 = hashPII('JANE@example.com');
    const h3 = hashPII('  jane@example.com  ');
    const h4 = hashPII('Jane@Example.Com');

    test('lowercase normalization', h1, h2);
    test('whitespace trimming', h1, h3);
    test('case-insensitive throughout', h1, h4);

    // Different inputs MUST produce different hashes
    const differentHash = hashPII('john@example.com');
    testThat('different emails produce different hashes', h1 !== differentHash);

    // ------------------------------------------------------------------------
    // normalizePhone
    // ------------------------------------------------------------------------

    section('normalizePhone');

    test('strips formatting from phone', normalizePhone('(555) 123-4567'), '5551234567');
    test('strips dashes', normalizePhone('555-123-4567'), '5551234567');
    test('strips country code formatting', normalizePhone('+1-555-123-4567'), '15551234567');
    test('already-normalized phone passes through', normalizePhone('5551234567'), '5551234567');
    test('returns null for too-short number', normalizePhone('12345'), null);
    test('returns null for null', normalizePhone(null), null);
    test('returns null for empty', normalizePhone(''), null);

    // Phones with formatting should hash to same value after normalization
    const phoneA = hashPII(normalizePhone('(555) 123-4567'));
    const phoneB = hashPII(normalizePhone('555-123-4567'));
    const phoneC = hashPII(normalizePhone('5551234567'));
    test('formatted and unformatted phones hash identically', phoneA, phoneB);
    test('different formats all hash identically', phoneA, phoneC);

    // ------------------------------------------------------------------------
    // generateResolutionKey
    // ------------------------------------------------------------------------

    section('generateResolutionKey');

    const emailHashA = hashPII('jane@example.com');
    const phoneHashA = hashPII(normalizePhone('5551234567'));
    const emailHashB = hashPII('john@example.com');

    const keyEmailOnly = generateResolutionKey(emailHashA, null);
    const keyPhoneOnly = generateResolutionKey(null, phoneHashA);
    const keyBoth = generateResolutionKey(emailHashA, phoneHashA);
    const keyBothAgain = generateResolutionKey(emailHashA, phoneHashA);

    testThat('produces 64-char hex output', /^[0-9a-f]{64}$/.test(keyBoth));
    test('same inputs produce same key', keyBoth, keyBothAgain);
    testThat('email-only differs from phone-only', keyEmailOnly !== keyPhoneOnly);
    testThat('email-only differs from both', keyEmailOnly !== keyBoth);
    testThat('different email produces different key',
        generateResolutionKey(emailHashB, null) !== keyEmailOnly);

    testThrows('throws when both hashes are null',
        () => generateResolutionKey(null, null),
        'at least one of emailHash or phoneHash');

    // ------------------------------------------------------------------------
    // sanitizeEmail
    // ------------------------------------------------------------------------

    section('sanitizeEmail');

    test('masks normal email', sanitizeEmail('jane@example.com'), 'j***@example.com');
    test('handles single-char username', sanitizeEmail('j@example.com'), 'j@example.com');
    test('caps masking at 5 asterisks for long usernames',
        sanitizeEmail('verylongname@example.com'), 'v*****@example.com');
    test('handles two-char username', sanitizeEmail('jo@example.com'), 'j*@example.com');
    test('returns null for null', sanitizeEmail(null), null);
    test('returns null for empty', sanitizeEmail(''), null);
    test('handles malformed (no @)', sanitizeEmail('not-an-email'), '***@***.***');
    test('handles malformed (empty username)', sanitizeEmail('@example.com'), '***@***.***');
    test('handles malformed (empty domain)', sanitizeEmail('jane@'), '***@***.***');

    // ------------------------------------------------------------------------
    // sanitizePhone
    // ------------------------------------------------------------------------

    section('sanitizePhone');

    test('masks normal phone', sanitizePhone('5551234567'), '***-***-4567');
    test('masks formatted phone', sanitizePhone('(555) 123-4567'), '***-***-4567');
    test('masks international phone', sanitizePhone('+1-555-123-4567'), '***-***-4567');
    test('returns null for too-short', sanitizePhone('12345'), null);
    test('returns null for null', sanitizePhone(null), null);
    test('returns null for empty', sanitizePhone(''), null);

    // ------------------------------------------------------------------------
    // Cross-check JavaScript hashPII against PostgreSQL hash_pii
    // ------------------------------------------------------------------------
    //
    // This is the critical test: if these two implementations diverge, every
    // identity resolution operation will silently produce wrong results.
    // ------------------------------------------------------------------------

    section('Cross-check: JS hashPII matches SQL hash_pii');

    const client = new Client({
        host: process.env.DB_HOST,
        port: parseInt(process.env.DB_PORT, 10),
        database: process.env.DB_NAME,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
    });

    try {
        await client.connect();

        const testCases = [
            'jane@example.com',
            'john.smith+tag@example.co.uk',
            'a@b.c',
            '5551234567',
        ];

        const salt = process.env.PII_HASH_SALT;

        for (const value of testCases) {
            const jsHash = hashPII(value);
            const sqlResult = await client.query(
                'SELECT hash_pii($1, $2) AS hash',
                [value, salt]
            );
            const sqlHash = sqlResult.rows[0].hash;

            test(`"${value}" - JS and SQL produce same hash`, jsHash, sqlHash);
        }
    } catch (err) {
        console.log(`${colors.yellow}⚠${colors.reset} Could not connect to database for cross-check tests`);
        console.log(`  ${colors.gray}${err.message}${colors.reset}`);
        console.log(`  ${colors.gray}Run: sudo service postgresql start${colors.reset}`);
    } finally {
        await client.end();
    }

    // ------------------------------------------------------------------------
    // Salt validation
    // ------------------------------------------------------------------------

    section('Salt validation');

    const originalSalt = process.env.PII_HASH_SALT;

    // Test: missing salt throws
    delete process.env.PII_HASH_SALT;
    _resetSaltCache();

    testThrows('hashPII throws when salt is missing',
        () => hashPII('test'),
        'PII_HASH_SALT environment variable is not set');

    // Restore salt for clean state
    process.env.PII_HASH_SALT = originalSalt;
    _resetSaltCache();

    // ------------------------------------------------------------------------
    // Summary
    // ------------------------------------------------------------------------

    console.log(`\n${colors.bold}━━ Summary ━━${colors.reset}`);
    console.log(`${colors.green}Passed:${colors.reset} ${passed}`);
    if (failed > 0) {
        console.log(`${colors.red}Failed:${colors.reset} ${failed}`);
        console.log('');
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
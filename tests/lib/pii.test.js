// ============================================================================
// ThreadOS Core - PII Scanner Tests
// ============================================================================
//
// Unit tests for src/lib/pii.js: the pattern list, scalar detection,
// recursion into objects/arrays/keys, and the never-echo-the-value property.
// These own the scanner INTERNALS; the events and consent test files keep
// their integration-level coverage of the scanner's call sites.
//
// Usage:
//   node tests/lib/pii.test.js
// ============================================================================

const { detectPiiInScalar, scanForPii } = require('../../src/lib/pii');

// ----------------------------------------------------------------------------
// Test runner state
// ----------------------------------------------------------------------------

let passed = 0;
let failed = 0;

const colors = {
    reset: '\x1b[0m',
    bold: '\x1b[1m',
    green: '\x1b[32m',
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
// Tests
// ----------------------------------------------------------------------------

console.log(`${colors.bold}ThreadOS Core - PII Scanner Tests${colors.reset}`);

// --------------------------------------------------------------------
section('Scalar detection: pattern list');
// --------------------------------------------------------------------

test('detects a bare email', detectPiiInScalar('jane@example.com'), 'email');
test('detects an email embedded in a larger string',
    detectPiiInScalar('contact jane@example.com for details'), 'email');
test('detects an SSN', detectPiiInScalar('123-45-6789'), 'ssn');
test('dashed SSN reports as ssn, not phone (pattern order)',
    detectPiiInScalar('my ssn is 123-45-6789 ok'), 'ssn');
test('detects a dashed NANP phone', detectPiiInScalar('555-123-4567'), 'phone');
test('detects a parenthesized NANP phone', detectPiiInScalar('(555) 123-4567'), 'phone');
test('detects a +1-prefixed dotted phone', detectPiiInScalar('+1 555.123.4567'), 'phone');
test('detects a separated international phone', detectPiiInScalar('+44 20 7946 0958'), 'phone');
test('detects an unseparated E.164 phone', detectPiiInScalar('+442079460958'), 'phone');

// --------------------------------------------------------------------
section('Scalar detection: deliberate non-matches (under-detect bias)');
// --------------------------------------------------------------------

test('bare 10-digit run is NOT matched (order-number bias)',
    detectPiiInScalar('5551234567'), null);
test('unseparated 11-digit run without + is NOT matched',
    detectPiiInScalar('12025551234'), null);
test('bare "+1" is NOT matched', detectPiiInScalar('+1'), null);
test('"+12345" (too short for E.164) is NOT matched', detectPiiInScalar('+12345'), null);
test('ordinary clean text is NOT matched', detectPiiInScalar('checkout completed'), null);

// --------------------------------------------------------------------
section('Scalar detection: type handling');
// --------------------------------------------------------------------

test('numbers are coerced to string and scanned (clean number)',
    detectPiiInScalar(4567), null);
test('booleans are not scanned', detectPiiInScalar(true), null);
test('null is not scanned', detectPiiInScalar(null), null);

// --------------------------------------------------------------------
section('Recursion: objects, arrays, keys');
// --------------------------------------------------------------------

test('clean nested structure yields no findings',
    scanForPii({ a: { b: ['x', 1] }, c: 'y' }), []);

test('finding in a nested object carries a dotted path',
    scanForPii({ user: { contact: 'jane@example.com' } }),
    [{ path: 'properties.user.contact', type: 'email' }]);

test('finding in an array carries a bracketed path',
    scanForPii({ notes: ['clean', '555-123-4567'] }),
    [{ path: 'properties.notes[1]', type: 'phone' }]);

test('custom root path is respected (non-events callers)',
    scanForPii('reach me at jane@example.com', 'capture_context'),
    [{ path: 'capture_context', type: 'email' }]);

test('multiple findings are all reported',
    scanForPii({ a: 'jane@example.com', b: '123-45-6789' }).length, 2);

// --------------------------------------------------------------------
section('Keys and the never-echo property');
// --------------------------------------------------------------------

const keyFindings = scanForPii({ 'jane@example.com': 'clicked' });
test('a PII key is itself a finding, reported by position',
    keyFindings, [{ path: 'properties[key#0]', type: 'email' }]);

const nestedUnderPiiKey = scanForPii({ 'jane@example.com': { deep: '555-123-4567' } });
testThat('a value nested under a PII key is still found',
    nestedUnderPiiKey.some(f => f.type === 'phone'),
    `findings: ${JSON.stringify(nestedUnderPiiKey)}`);
testThat('no finding path ever echoes the PII key text',
    !JSON.stringify(nestedUnderPiiKey).includes('jane@example.com'),
    `findings leaked the key: ${JSON.stringify(nestedUnderPiiKey)}`);
testThat('value findings never echo the matched value either',
    !JSON.stringify(scanForPii({ contact: 'jane@example.com' })).includes('jane@example.com'),
    'finding contained the raw email');

// ----------------------------------------------------------------------------
// Summary
// ----------------------------------------------------------------------------

console.log(`\n${colors.bold}━━ Summary ━━${colors.reset}`);
console.log(`${colors.green}Passed:${colors.reset} ${passed}`);
if (failed > 0) {
    console.log(`${colors.red}Failed:${colors.reset} ${failed}`);
    process.exit(1);
} else {
    console.log(`${colors.gray}No failures.${colors.reset}`);
}

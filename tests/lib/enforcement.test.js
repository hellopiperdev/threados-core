// ============================================================================
// ThreadOS Core - Consent Enforcement Rule Tests
// ============================================================================
//
// Unit tests for src/lib/enforcement.js: every cell of the 18-cell
// basis x posture rule map is asserted against its FULL expected purpose
// set (not just representative purposes), plus the evaluateCapture
// invariants: no-record rejection, deny-precedence, basis filtering, and
// latest-effective_from authorization.
//
// Usage:
//   node tests/lib/enforcement.test.js
// ============================================================================

const { CAPTURE_RULES, evaluateBasis, evaluateCapture } = require('../../src/lib/enforcement');

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
// The expected map, restated independently from the ruling (a transcription
// error in enforcement.js and an identical error here would have to be made
// twice to slip through).
// ----------------------------------------------------------------------------

const PURPOSES = ['marketing', 'personalization', 'analytics',
    'service_operations', 'legal_compliance', 'fraud_prevention'];
const ALL = PURPOSES;
const OPERATIONAL = ['service_operations', 'fraud_prevention'];
const EXPECTED = {
    strict: {
        active_consent: ALL,
        documented_opt_in: ALL,
        legitimate_interest: [],
        contract: [],
        legal_obligation: ['legal_compliance'],
        undocumented: [],
    },
    standard: {
        active_consent: ALL,
        documented_opt_in: ALL,
        legitimate_interest: OPERATIONAL,
        contract: ['service_operations'],
        legal_obligation: ['legal_compliance'],
        undocumented: [],
    },
    legacy: {
        active_consent: ALL,
        documented_opt_in: ALL,
        legitimate_interest: OPERATIONAL,
        contract: ['service_operations'],
        legal_obligation: ['legal_compliance'],
        undocumented: ['service_operations', 'legal_compliance', 'fraud_prevention'],
    },
};

// Helper to build consent rows for evaluateCapture.
function row(overrides = {}) {
    return {
        state: 'granted',
        consent_basis: 'active_consent',
        effective_from: '2026-06-01T00:00:00.000Z',
        record_id: 'rec-default',
        ...overrides,
    };
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

console.log(`${colors.bold}ThreadOS Core - Consent Enforcement Rule Tests${colors.reset}`);

// --------------------------------------------------------------------
section('The rule map: all 18 basis x posture cells, full purpose sets');
// --------------------------------------------------------------------

for (const posture of Object.keys(EXPECTED)) {
    for (const basis of Object.keys(EXPECTED[posture])) {
        const allowed = PURPOSES.filter(p => evaluateBasis(posture, basis, p));
        test(`${posture} x ${basis} allows exactly [${EXPECTED[posture][basis].join(', ') || 'nothing'}]`,
            allowed, EXPECTED[posture][basis]);
    }
}

// --------------------------------------------------------------------
section('Map integrity');
// --------------------------------------------------------------------

testThat('the rule map is frozen (consent law is not runtime-mutable)',
    Object.isFrozen(CAPTURE_RULES) &&
    Object.isFrozen(CAPTURE_RULES.strict) &&
    Object.isFrozen(CAPTURE_RULES.strict.active_consent));
test('analytics is consent-gated under EVERY posture x non-consent basis',
    ['strict', 'standard', 'legacy'].flatMap(posture =>
        ['legitimate_interest', 'contract', 'legal_obligation', 'undocumented']
            .filter(basis => evaluateBasis(posture, basis, 'analytics'))),
    []);
test('marketing/personalization never pass without active consent or opt-in',
    ['strict', 'standard', 'legacy'].flatMap(posture =>
        ['legitimate_interest', 'contract', 'legal_obligation', 'undocumented']
            .flatMap(basis => ['marketing', 'personalization']
                .filter(p => evaluateBasis(posture, basis, p)))),
    []);

// --------------------------------------------------------------------
section('Fail-closed on unknown vocabulary');
// --------------------------------------------------------------------

test('unknown posture denies', evaluateBasis('permissive', 'active_consent', 'analytics'), false);
test('unknown basis denies', evaluateBasis('strict', 'verbal_promise', 'analytics'), false);
test('unknown purpose denies', evaluateBasis('strict', 'active_consent', 'surveillance'), false);

// --------------------------------------------------------------------
section('evaluateCapture: invariants');
// --------------------------------------------------------------------

test('no rows -> rejected as no_consent_record',
    evaluateCapture([], 'legacy', 'service_operations'),
    { allowed: false, reason: 'no_consent_record' });

test('a denied row rejects even alongside a valid grant (deny-precedence)',
    evaluateCapture([
        row({ record_id: 'grant' }),
        row({ state: 'denied', record_id: 'denial' }),
    ], 'strict', 'analytics').reason, 'consent_denied');

test('a withdrawn row rejects even alongside a valid grant',
    evaluateCapture([
        row({ record_id: 'grant' }),
        row({ state: 'withdrawn', record_id: 'withdrawal' }),
    ], 'strict', 'analytics').reason, 'consent_withdrawn');

test('deny-precedence cites the blocking record',
    evaluateCapture([row(), row({ state: 'denied', record_id: 'the-denial' })],
        'strict', 'analytics').record_id, 'the-denial');

test('granted rows with insufficient basis -> basis_insufficient',
    evaluateCapture([row({ consent_basis: 'undocumented' })],
        'standard', 'service_operations').reason, 'basis_insufficient');

test('a single passing grant authorizes',
    evaluateCapture([row({ record_id: 'the-grant' })], 'strict', 'analytics'),
    {
        allowed: true, basis: 'active_consent', record_id: 'the-grant',
        effective_from: '2026-06-01T00:00:00.000Z',
    });

test('among passing grants, the LATEST effective_from authorizes',
    evaluateCapture([
        row({ record_id: 'older', effective_from: '2026-01-01T00:00:00.000Z' }),
        row({ record_id: 'newer', effective_from: '2026-06-15T00:00:00.000Z' }),
        row({ record_id: 'middle', effective_from: '2026-03-01T00:00:00.000Z' }),
    ], 'strict', 'analytics').record_id, 'newer');

test('a non-passing grant does not block a passing one (only denials block)',
    evaluateCapture([
        row({ consent_basis: 'undocumented', record_id: 'weak' }),
        row({ consent_basis: 'active_consent', record_id: 'strong' }),
    ], 'standard', 'analytics').record_id, 'strong');

test('mixed bases: the passing row wins even if a non-passing row is newer',
    evaluateCapture([
        row({ consent_basis: 'undocumented', record_id: 'weak-newer', effective_from: '2026-06-20T00:00:00.000Z' }),
        row({ consent_basis: 'documented_opt_in', record_id: 'strong-older', effective_from: '2026-02-01T00:00:00.000Z' }),
    ], 'standard', 'analytics').record_id, 'strong-older');

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

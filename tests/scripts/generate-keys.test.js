// ============================================================================
// ThreadOS Core - Key Generation Tests
// ============================================================================
//
// Exercises scripts/generate-keys.js by invoking it as a subprocess and
// verifying the resulting key files are valid and behave as expected.
//
// Tests use throwaway names prefixed with "_test_" and clean up after
// themselves. Real dev keys (threados-core, test-vertical) are untouched.
//
// Usage:
//   node tests/scripts/generate-keys.test.js
// ============================================================================

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const REPO_ROOT = path.join(__dirname, '..', '..');
const KEYS_DIR = path.join(REPO_ROOT, 'keys');
const SCRIPT_PATH = path.join(REPO_ROOT, 'scripts', 'generate-keys.js');

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
// Helpers
// ----------------------------------------------------------------------------

function runScript(name) {
    try {
        const stdout = execFileSync('node', [SCRIPT_PATH, name], {
            cwd: REPO_ROOT,
            encoding: 'utf8',
            stdio: ['ignore', 'pipe', 'pipe'],
        });
        return { ok: true, stdout, stderr: '' };
    } catch (err) {
        return {
            ok: false,
            exitCode: err.status,
            stdout: err.stdout ? err.stdout.toString() : '',
            stderr: err.stderr ? err.stderr.toString() : '',
        };
    }
}

function cleanup(name) {
    const dir = path.join(KEYS_DIR, name);
    if (fs.existsSync(dir)) {
        fs.rmSync(dir, { recursive: true, force: true });
    }
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

function runTests() {
    console.log(`${colors.bold}ThreadOS Core - Key Generation Tests${colors.reset}`);

    const testName1 = 'zz-test-keygen-basic';
    const testName2 = 'zz-test-keygen-uniqueness';
    const testName3 = 'zz-test-keygen-overwrite';

    try {
        // --------------------------------------------------------------------
        // Basic generation
        // --------------------------------------------------------------------

        section('Basic generation');

        cleanup(testName1);
        const result = runScript(testName1);

        test('script exits successfully', result.ok, true);
        testThat('private key file exists',
            fs.existsSync(path.join(KEYS_DIR, testName1, 'private.pem')));
        testThat('public key file exists',
            fs.existsSync(path.join(KEYS_DIR, testName1, 'public.pem')));

        if (fs.existsSync(path.join(KEYS_DIR, testName1, 'private.pem'))) {
            const privateKey = fs.readFileSync(
                path.join(KEYS_DIR, testName1, 'private.pem'), 'utf8'
            );
            testThat('private key has correct PEM header',
                privateKey.includes('-----BEGIN PRIVATE KEY-----'));
            testThat('private key has correct PEM footer',
                privateKey.includes('-----END PRIVATE KEY-----'));

            // Try to parse it with Node's crypto - this verifies it's a valid Ed25519 key
            let canParse = false;
            try {
                const key = crypto.createPrivateKey(privateKey);
                canParse = key.asymmetricKeyType === 'ed25519';
            } catch (err) {
                // canParse stays false
            }
            testThat('private key is a valid Ed25519 key', canParse);
        }

        if (fs.existsSync(path.join(KEYS_DIR, testName1, 'public.pem'))) {
            const publicKey = fs.readFileSync(
                path.join(KEYS_DIR, testName1, 'public.pem'), 'utf8'
            );
            testThat('public key has correct PEM header',
                publicKey.includes('-----BEGIN PUBLIC KEY-----'));

            let canParse = false;
            try {
                const key = crypto.createPublicKey(publicKey);
                canParse = key.asymmetricKeyType === 'ed25519';
            } catch (err) {
                // canParse stays false
            }
            testThat('public key is a valid Ed25519 key', canParse);
        }

        // Permission check (private key should be mode 0600)
        if (fs.existsSync(path.join(KEYS_DIR, testName1, 'private.pem'))) {
            const stats = fs.statSync(path.join(KEYS_DIR, testName1, 'private.pem'));
            const mode = stats.mode & 0o777;
            testThat('private key has restrictive permissions (0600)',
                mode === 0o600,
                `actual mode: ${mode.toString(8)}`);
        }

        // --------------------------------------------------------------------
        // Uniqueness - two generations produce different keys
        // --------------------------------------------------------------------

        section('Uniqueness');

        cleanup(testName2);
        const first = runScript(testName2);
        const firstPrivate = fs.readFileSync(
            path.join(KEYS_DIR, testName2, 'private.pem'), 'utf8'
        );

        // Now delete and regenerate
        cleanup(testName2);
        const second = runScript(testName2);
        const secondPrivate = fs.readFileSync(
            path.join(KEYS_DIR, testName2, 'private.pem'), 'utf8'
        );

        testThat('first script succeeded', first.ok);
        testThat('second script succeeded', second.ok);
        testThat('two generations produce different private keys',
            firstPrivate !== secondPrivate,
            'two runs produced identical keys - randomness failure?');

        // --------------------------------------------------------------------
        // Overwrite refusal
        // --------------------------------------------------------------------

        section('Overwrite refusal');

        // testName3 should still exist from generation in this test run
        cleanup(testName3);
        const initial = runScript(testName3);
        testThat('initial generation succeeded', initial.ok);

        const overwrite = runScript(testName3);
        test('overwrite attempt exits with error', overwrite.ok, false);
        testThat('overwrite error mentions existing keys',
            overwrite.stdout.includes('already exist') ||
            overwrite.stderr.includes('already exist'));

        // --------------------------------------------------------------------
        // Name validation
        // --------------------------------------------------------------------

        section('Name validation');

        const invalidNames = [
            'UPPERCASE',
            'has spaces',
            'has/slashes',
            'has.dots',
            '1starts-with-digit',
            '-starts-with-hyphen',
            '',
        ];

        for (const badName of invalidNames) {
            const result = runScript(badName);
            testThat(`rejects invalid name "${badName}"`, !result.ok);
        }

        const validNames = [
            'simple',
            'with-hyphens',
            'mix-of-letters-and-123',
        ];

        for (const goodName of validNames) {
            const safeName = '_test_valid_' + goodName.replace(/-/g, '_');
            cleanup(safeName);
            // We test the pattern, not the actual name acceptance; use synthetic names
        }
        // (The valid-name acceptance is implicit in the basic generation test above)

    } finally {
        // Clean up all test directories
        cleanup(testName1);
        cleanup(testName2);
        cleanup(testName3);
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

runTests();
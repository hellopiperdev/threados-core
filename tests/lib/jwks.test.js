// ============================================================================
// ThreadOS Core - JWKS Tests
// ============================================================================
//
// Exercises src/lib/jwks.js (core JWKS document, fetch/cache for verticals)
// and the /.well-known/jwks.json HTTP endpoint.
//
// For the vertical-fetch tests, we spin up a small mock JWKS server inside
// this test file so we can control responses precisely (including failures)
// without depending on external services.
//
// Usage:
//   node tests/lib/jwks.test.js
// ============================================================================

require('dotenv').config();

const http = require('http');
const crypto = require('crypto');
const { createServer } = require('../../src/server');
const {
    getCoreJwks,
    getJwksForVertical,
    findKeyByKid,
    pemPublicKeyToJwk,
    computeKid,
    _resetCoreJwksCache,
    _resetVerticalJwksCache,
} = require('../../src/lib/jwks');

const APP_PORT = 3003;
const MOCK_JWKS_PORT = 3004;

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

async function testThrowsAsync(name, fn, expectedMessageFragment) {
    try {
        await fn();
        failed++;
        console.log(`${colors.red}✗${colors.reset} ${name} (expected error, none thrown)`);
    } catch (err) {
        if (err.message.includes(expectedMessageFragment)) {
            passed++;
            console.log(`${colors.green}✓${colors.reset} ${name}`);
        } else {
            failed++;
            console.log(`${colors.red}✗${colors.reset} ${name}`);
            console.log(`  ${colors.gray}expected error containing:${colors.reset} ${expectedMessageFragment}`);
            console.log(`  ${colors.gray}actual error:             ${colors.reset} ${err.message}`);
        }
    }
}

// ----------------------------------------------------------------------------
// HTTP request helper
// ----------------------------------------------------------------------------

function httpGet(port, path) {
    return new Promise((resolve, reject) => {
        const req = http.request({
            hostname: 'localhost',
            port,
            path,
            method: 'GET',
        }, (res) => {
            let data = '';
            res.on('data', chunk => { data += chunk; });
            res.on('end', () => {
                let body = data;
                try { body = JSON.parse(data); } catch (_) {}
                resolve({ statusCode: res.statusCode, headers: res.headers, body });
            });
        });
        req.on('error', reject);
        req.end();
    });
}

// ----------------------------------------------------------------------------
// Mock JWKS server
// ----------------------------------------------------------------------------
//
// A tiny HTTP server we control completely. Each test path can be
// configured to return different responses for testing the fetch/cache
// logic against known scenarios.
// ----------------------------------------------------------------------------

let mockServer = null;
let mockResponses = {};   // path -> { statusCode, body } or 'timeout'
let mockHitCount = {};    // path -> count of how many times fetched

function startMockServer() {
    return new Promise((resolve) => {
        mockServer = http.createServer((req, res) => {
            mockHitCount[req.url] = (mockHitCount[req.url] || 0) + 1;
            const config = mockResponses[req.url];

            if (!config) {
                res.statusCode = 404;
                res.end('not configured');
                return;
            }

            if (config === 'timeout') {
                // Never respond - lets us test the timeout path
                return;
            }

            res.statusCode = config.statusCode || 200;
            res.setHeader('Content-Type', 'application/json');
            res.end(typeof config.body === 'string'
                ? config.body
                : JSON.stringify(config.body));
        });
        mockServer.listen(MOCK_JWKS_PORT, () => resolve());
    });
}

function stopMockServer() {
    return new Promise((resolve) => {
        if (mockServer) {
            mockServer.close(() => resolve());
        } else {
            resolve();
        }
    });
}

function mockUrl(path) {
    return `http://localhost:${MOCK_JWKS_PORT}${path}`;
}

// ----------------------------------------------------------------------------
// Setup and teardown for app server
// ----------------------------------------------------------------------------

let appServer = null;

async function startApp() {
    const app = createServer();
    return new Promise((resolve) => {
        appServer = app.listen(APP_PORT, resolve);
    });
}

async function stopApp() {
    return new Promise((resolve) => {
        if (appServer) {
            appServer.close(resolve);
        } else {
            resolve();
        }
    });
}

// ----------------------------------------------------------------------------
// Generate a test JWKS document for mock responses
// ----------------------------------------------------------------------------

function generateTestJwks() {
    const { publicKey } = crypto.generateKeyPairSync('ed25519', {
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    const kid = computeKid(publicKey);
    const jwk = pemPublicKeyToJwk(publicKey, kid);

    return { jwks: { keys: [jwk] }, kid };
}

// ----------------------------------------------------------------------------
// Main test execution
// ----------------------------------------------------------------------------

async function runTests() {
    console.log(`${colors.bold}ThreadOS Core - JWKS Tests${colors.reset}`);

    try {
        section('Setup');
        await startApp();
        console.log(`${colors.green}✓${colors.reset} App server running on port ${APP_PORT}`);
        await startMockServer();
        console.log(`${colors.green}✓${colors.reset} Mock JWKS server running on port ${MOCK_JWKS_PORT}`);

        // --------------------------------------------------------------------
        // Core JWKS endpoint
        // --------------------------------------------------------------------

        section('Core JWKS endpoint');

        const response = await httpGet(APP_PORT, '/.well-known/jwks.json');

        test('endpoint returns 200', response.statusCode, 200);
        testThat('Content-Type is JSON',
            (response.headers['content-type'] || '').includes('application/json'));
        testThat('Cache-Control header is set',
            (response.headers['cache-control'] || '').includes('max-age'));

        testThat('response has keys array',
            Array.isArray(response.body.keys));
        testThat('keys array has at least one entry',
            response.body.keys && response.body.keys.length > 0);

        if (response.body.keys && response.body.keys.length > 0) {
            const key = response.body.keys[0];
            test('kty is OKP', key.kty, 'OKP');
            test('crv is Ed25519', key.crv, 'Ed25519');
            test('alg is EdDSA', key.alg, 'EdDSA');
            test('use is sig', key.use, 'sig');
            testThat('x has base64url material',
                typeof key.x === 'string' && key.x.length > 0);
            testThat('kid is a hex string',
                typeof key.kid === 'string' && /^[0-9a-f]+$/.test(key.kid));
        }

        // --------------------------------------------------------------------
        // getCoreJwks direct call
        // --------------------------------------------------------------------

        section('getCoreJwks direct call');

        _resetCoreJwksCache();
        const direct1 = getCoreJwks();
        const direct2 = getCoreJwks();

        testThat('returns an object with keys array',
            direct1.keys && Array.isArray(direct1.keys));
        testThat('cached result is same reference (memoized)',
            direct1 === direct2);

        // --------------------------------------------------------------------
        // pemPublicKeyToJwk
        // --------------------------------------------------------------------

        section('pemPublicKeyToJwk');

        const { publicKey: testPem } = crypto.generateKeyPairSync('ed25519', {
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        });

        const testJwk = pemPublicKeyToJwk(testPem, 'test-kid');

        test('kty is OKP', testJwk.kty, 'OKP');
        test('crv is Ed25519', testJwk.crv, 'Ed25519');
        test('kid passed through', testJwk.kid, 'test-kid');
        test('alg is EdDSA', testJwk.alg, 'EdDSA');
        test('use is sig', testJwk.use, 'sig');
        testThat('x is non-empty', testJwk.x && testJwk.x.length > 0);

        // Non-Ed25519 key should fail
        const { publicKey: rsaPem } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        });

        let rejectedRsa = false;
        try {
            pemPublicKeyToJwk(rsaPem, 'rsa-kid');
        } catch (err) {
            rejectedRsa = err.message.includes('Ed25519');
        }
        testThat('rejects non-Ed25519 keys', rejectedRsa);

        // --------------------------------------------------------------------
        // computeKid stability
        // --------------------------------------------------------------------

        section('computeKid');

        const kid1 = computeKid(testPem);
        const kid2 = computeKid(testPem);
        test('same key produces same kid', kid1, kid2);
        testThat('kid is 16 hex chars',
            typeof kid1 === 'string' && /^[0-9a-f]{16}$/.test(kid1));

        const { publicKey: differentPem } = crypto.generateKeyPairSync('ed25519', {
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        });
        const kid3 = computeKid(differentPem);
        testThat('different keys produce different kids', kid1 !== kid3);

        // --------------------------------------------------------------------
        // getJwksForVertical: cache miss, fetch fresh
        // --------------------------------------------------------------------

        section('getJwksForVertical: basic fetch');

        _resetVerticalJwksCache();
        mockResponses = {};
        mockHitCount = {};

        const { jwks: testJwksDoc } = generateTestJwks();
        mockResponses['/jwks'] = { statusCode: 200, body: testJwksDoc };

        const fetched = await getJwksForVertical(mockUrl('/jwks'), 3600);
        test('returns the JWKS document', fetched, testJwksDoc);
        test('hit the mock server once', mockHitCount['/jwks'], 1);

        // --------------------------------------------------------------------
        // getJwksForVertical: cache hit (no second fetch)
        // --------------------------------------------------------------------

        section('getJwksForVertical: cache hit');

        const fetchedAgain = await getJwksForVertical(mockUrl('/jwks'), 3600);
        test('returns same document', fetchedAgain, testJwksDoc);
        test('did NOT hit the mock server again', mockHitCount['/jwks'], 1);

        // --------------------------------------------------------------------
        // getJwksForVertical: cache expiry
        // --------------------------------------------------------------------

        section('getJwksForVertical: cache expiry');

        _resetVerticalJwksCache();
        mockHitCount = {};

        // Set up a path that will return updated content the second time
        let callCount = 0;
        mockResponses['/expiring'] = { statusCode: 200, body: testJwksDoc };

        // Fetch with a 0-second TTL (immediately expired)
        await getJwksForVertical(mockUrl('/expiring'), 0);
        // Wait a tick to ensure the timestamp comparison treats it as expired
        await new Promise(r => setTimeout(r, 50));
        await getJwksForVertical(mockUrl('/expiring'), 0);

        test('cache with 0 TTL fetches twice', mockHitCount['/expiring'], 2);

        // --------------------------------------------------------------------
        // getJwksForVertical: error cases
        // --------------------------------------------------------------------

        section('getJwksForVertical: error cases');

        _resetVerticalJwksCache();

        mockResponses['/404'] = { statusCode: 404, body: 'not found' };
        await testThrowsAsync(
            'throws on 404 response',
            () => getJwksForVertical(mockUrl('/404'), 3600),
            'returned 404'
        );

        mockResponses['/500'] = { statusCode: 500, body: 'oops' };
        await testThrowsAsync(
            'throws on 500 response',
            () => getJwksForVertical(mockUrl('/500'), 3600),
            'returned 500'
        );

        mockResponses['/bad-json'] = { statusCode: 200, body: 'not actually json' };
        await testThrowsAsync(
            'throws on invalid JSON',
            () => getJwksForVertical(mockUrl('/bad-json'), 3600),
            'not valid JSON'
        );

        mockResponses['/no-keys'] = { statusCode: 200, body: { something: 'else' } };
        await testThrowsAsync(
            'throws when response is missing keys array',
            () => getJwksForVertical(mockUrl('/no-keys'), 3600),
            'missing "keys" array'
        );

        await testThrowsAsync(
            'throws on connection refused',
            () => getJwksForVertical('http://localhost:1/jwks', 3600),
            'fetch failed'
        );

        // --------------------------------------------------------------------
        // findKeyByKid
        // --------------------------------------------------------------------

        section('findKeyByKid');

        const { jwks: multiKeyJwks, kid: knownKid } = generateTestJwks();

        const foundKey = findKeyByKid(multiKeyJwks, knownKid);
        testThat('finds existing key by kid', foundKey && foundKey.kid === knownKid);

        const notFound = findKeyByKid(multiKeyJwks, 'nonexistent-kid');
        test('returns null for unknown kid', notFound, null);

        const nullCase = findKeyByKid(null, 'any');
        test('handles null jwks gracefully', nullCase, null);

        const noKeysCase = findKeyByKid({}, 'any');
        test('handles jwks with no keys array', noKeysCase, null);

    } finally {
        section('Teardown');
        try {
            await stopApp();
            await stopMockServer();
            console.log(`${colors.green}✓${colors.reset} Servers stopped`);
        } catch (err) {
            console.log(`${colors.yellow}⚠${colors.reset} Teardown error: ${err.message}`);
        }
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
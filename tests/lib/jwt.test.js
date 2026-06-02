// ============================================================================
// ThreadOS Core - JWT Tests
// ============================================================================
//
// Exercises src/lib/jwt.js: signing, verification, and the security-relevant
// failure modes that JWT libraries must handle correctly.
//
// Each test verifies one specific property. Many tests target attack
// scenarios (algorithm confusion, signature tampering, etc.) so that
// regressions on security-critical paths surface immediately.
//
// Usage:
//   node tests/lib/jwt.test.js
// ============================================================================

const crypto = require('crypto');
const {
    signToken,
    verifyToken,
    decodeUnverified,
    JwtMalformedError,
    JwtSignatureError,
    JwtExpiredError,
    JwtClaimError,
    CLOCK_SKEW_SECONDS,
    MAX_TOKEN_LIFETIME_SECONDS,
} = require('../../src/lib/jwt');
const { computeKid } = require('../../src/lib/jwks');

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

function testThrows(name, fn, ExpectedErrorClass, messageFragment) {
    try {
        fn();
        failed++;
        console.log(`${colors.red}✗${colors.reset} ${name} (expected error, none thrown)`);
    } catch (err) {
        const correctClass = !ExpectedErrorClass || err instanceof ExpectedErrorClass;
        const correctMessage = !messageFragment || err.message.includes(messageFragment);
        if (correctClass && correctMessage) {
            passed++;
            console.log(`${colors.green}✓${colors.reset} ${name}`);
        } else {
            failed++;
            console.log(`${colors.red}✗${colors.reset} ${name}`);
            if (!correctClass) {
                console.log(`  ${colors.gray}expected class:${colors.reset} ${ExpectedErrorClass.name}`);
                console.log(`  ${colors.gray}actual class:  ${colors.reset} ${err.constructor.name}`);
            }
            if (!correctMessage) {
                console.log(`  ${colors.gray}expected message containing:${colors.reset} ${messageFragment}`);
                console.log(`  ${colors.gray}actual message:             ${colors.reset} ${err.message}`);
            }
        }
    }
}

// ----------------------------------------------------------------------------
// Test fixtures
// ----------------------------------------------------------------------------

function generateKeypair() {
    return crypto.generateKeyPairSync('ed25519', {
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
}

const keypair = generateKeypair();
const otherKeypair = generateKeypair();   // For "wrong key" tests
const testKid = computeKid(keypair.publicKey);
const otherKid = computeKid(otherKeypair.publicKey);

function baseClaims(overrides = {}) {
    const now = Math.floor(Date.now() / 1000);
    return {
        iss: 'test-vertical',
        sub: '00000000-0000-0000-0000-000000000001',
        iat: now,
        exp: now + 3600,
        ...overrides,
    };
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

function runTests() {
    console.log(`${colors.bold}ThreadOS Core - JWT Tests${colors.reset}`);

    // ------------------------------------------------------------------------
    // Sign and verify - happy path
    // ------------------------------------------------------------------------

    section('Sign and verify happy path');

    const validToken = signToken(baseClaims(), keypair.privateKey, testKid);

    testThat('signed token is a string', typeof validToken === 'string');
    testThat('token has three parts', validToken.split('.').length === 3);

    const verified = verifyToken(validToken, keypair.publicKey);
    test('verified payload contains iss', verified.iss, 'test-vertical');
    test('verified payload contains sub', verified.sub, '00000000-0000-0000-0000-000000000001');
    testThat('verified payload contains iat', typeof verified.iat === 'number');
    testThat('verified payload contains exp', typeof verified.exp === 'number');

    // ------------------------------------------------------------------------
    // Header validation
    // ------------------------------------------------------------------------

    section('Header validation');

    const decoded = decodeUnverified(validToken);
    test('header alg is EdDSA', decoded.header.alg, 'EdDSA');
    test('header typ is JWT', decoded.header.typ, 'JWT');
    test('header kid matches', decoded.header.kid, testKid);

    // ------------------------------------------------------------------------
    // Algorithm pinning - the famous vulnerability
    // ------------------------------------------------------------------------
    //
    // The classic JWT attack: alter the header to claim a different
    // algorithm. Our verifier must reject this.
    // ------------------------------------------------------------------------

    section('Algorithm pinning');

    // Forge a token claiming alg=none
    const noneHeader = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT', kid: testKid })).toString('base64url');
    const validPayload = validToken.split('.')[1];
    const noneToken = `${noneHeader}.${validPayload}.`;

    testThrows(
        'rejects alg=none',
        () => verifyToken(noneToken, keypair.publicKey),
        JwtMalformedError,
        'unsupported algorithm'
    );

    // Forge a token claiming alg=HS256 (the classic confusion attack)
    const hsHeader = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT', kid: testKid })).toString('base64url');
    const hsToken = `${hsHeader}.${validPayload}.fakesig`;

    testThrows(
        'rejects alg=HS256',
        () => verifyToken(hsToken, keypair.publicKey),
        JwtMalformedError,
        'unsupported algorithm'
    );

    // Empty alg
    const emptyAlgHeader = Buffer.from(JSON.stringify({ alg: '', typ: 'JWT', kid: testKid })).toString('base64url');
    testThrows(
        'rejects empty alg',
        () => verifyToken(`${emptyAlgHeader}.${validPayload}.fakesig`, keypair.publicKey),
        JwtMalformedError,
        'unsupported algorithm'
    );

    // ------------------------------------------------------------------------
    // Type validation
    // ------------------------------------------------------------------------

    section('Type validation');

    const wrongTypHeader = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'OTHER', kid: testKid })).toString('base64url');
    testThrows(
        'rejects wrong typ',
        () => verifyToken(`${wrongTypHeader}.${validPayload}.fakesig`, keypair.publicKey),
        JwtMalformedError,
        'unsupported type'
    );

    const noKidHeader = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT' })).toString('base64url');
    testThrows(
        'rejects missing kid',
        () => verifyToken(`${noKidHeader}.${validPayload}.fakesig`, keypair.publicKey),
        JwtMalformedError,
        'missing kid'
    );

    // ------------------------------------------------------------------------
    // Signature verification
    // ------------------------------------------------------------------------

    section('Signature verification');

    // Tamper with the payload
    const tamperedPayload = Buffer.from(JSON.stringify(
        baseClaims({ sub: '99999999-9999-9999-9999-999999999999' })
    )).toString('base64url');
    const tamperedToken = `${validToken.split('.')[0]}.${tamperedPayload}.${validToken.split('.')[2]}`;

    testThrows(
        'rejects tampered payload',
        () => verifyToken(tamperedToken, keypair.publicKey),
        JwtSignatureError,
        'signature verification failed'
    );

    // Wrong key entirely
    testThrows(
        'rejects valid token with wrong public key',
        () => verifyToken(validToken, otherKeypair.publicKey),
        JwtSignatureError
    );

    // Corrupted signature
    const corruptedToken = validToken.slice(0, -10) + 'AAAAAAAAAA';
    testThrows(
        'rejects corrupted signature',
        () => verifyToken(corruptedToken, keypair.publicKey),
        JwtSignatureError
    );

    // ------------------------------------------------------------------------
    // Required claim validation
    // ------------------------------------------------------------------------

    section('Required claim validation');

    testThrows(
        'rejects token without iss',
        () => {
            const noIss = signToken(baseClaims({ iss: undefined }), keypair.privateKey, testKid);
            verifyToken(noIss, keypair.publicKey);
        },
        Error,
        'iss claim is required'
    );

    testThrows(
        'rejects token without sub',
        () => {
            const noSub = signToken(baseClaims({ sub: undefined }), keypair.privateKey, testKid);
            verifyToken(noSub, keypair.publicKey);
        },
        Error,
        'sub claim is required'
    );

    // Build manually to bypass signToken validation
    function buildTokenManually(payload) {
        const header = { alg: 'EdDSA', typ: 'JWT', kid: testKid };
        const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
        const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
        const signingInput = `${headerB64}.${payloadB64}`;
        const keyObject = crypto.createPrivateKey(keypair.privateKey);
        const signature = crypto.sign(null, Buffer.from(signingInput, 'utf8'), keyObject);
        return `${signingInput}.${signature.toString('base64url')}`;
    }

    const noIatToken = buildTokenManually(baseClaims({ iat: undefined }));
    testThrows(
        'rejects token with missing iat',
        () => verifyToken(noIatToken, keypair.publicKey),
        JwtClaimError,
        'iat'
    );

    const noExpToken = buildTokenManually(baseClaims({ exp: undefined }));
    testThrows(
        'rejects token with missing exp',
        () => verifyToken(noExpToken, keypair.publicKey),
        JwtClaimError,
        'exp'
    );

    const nonStringIssToken = buildTokenManually(baseClaims({ iss: 123 }));
    testThrows(
        'rejects non-string iss',
        () => verifyToken(nonStringIssToken, keypair.publicKey),
        JwtClaimError,
        'iss'
    );

    // ------------------------------------------------------------------------
    // Timing validation
    // ------------------------------------------------------------------------

    section('Timing validation');

    const now = Math.floor(Date.now() / 1000);

    // Expired token (well past skew tolerance)
    const expiredToken = buildTokenManually({
        iss: 'test-vertical',
        sub: 'tenant',
        iat: now - 7200,
        exp: now - 3600,
    });
    testThrows(
        'rejects expired token',
        () => verifyToken(expiredToken, keypair.publicKey),
        JwtExpiredError,
        'expired'
    );

    // Future-dated token (well past skew tolerance)
    const futureToken = buildTokenManually({
        iss: 'test-vertical',
        sub: 'tenant',
        iat: now + 3600,
        exp: now + 7200,
    });
    testThrows(
        'rejects future-dated iat',
        () => verifyToken(futureToken, keypair.publicKey),
        JwtClaimError,
        'future'
    );

    // Just-expired token within skew tolerance - should pass
    const justExpired = buildTokenManually({
        iss: 'test-vertical',
        sub: 'tenant',
        iat: now - 3600,
        exp: now - 5,   // Within skew tolerance
    });
    let accepted = false;
    try {
        verifyToken(justExpired, keypair.publicKey);
        accepted = true;
    } catch (_) {}
    testThat('accepts token expired within skew tolerance', accepted);

    // Token with excessive lifetime
    const longLivedToken = buildTokenManually({
        iss: 'test-vertical',
        sub: 'tenant',
        iat: now,
        exp: now + MAX_TOKEN_LIFETIME_SECONDS + 60,
    });
    testThrows(
        'rejects token with excessive lifetime',
        () => verifyToken(longLivedToken, keypair.publicKey),
        JwtClaimError,
        'lifetime'
    );

    // Token at exact max lifetime is okay
    const maxLifetimeToken = buildTokenManually({
        iss: 'test-vertical',
        sub: 'tenant',
        iat: now,
        exp: now + MAX_TOKEN_LIFETIME_SECONDS,
    });
    let maxAccepted = false;
    try {
        verifyToken(maxLifetimeToken, keypair.publicKey);
        maxAccepted = true;
    } catch (err) {
        // failure
    }
    testThat('accepts token at exact max lifetime', maxAccepted);

    // ------------------------------------------------------------------------
    // Malformed token structures
    // ------------------------------------------------------------------------

    section('Malformed token structures');

    testThrows(
        'rejects empty string',
        () => verifyToken('', keypair.publicKey),
        JwtMalformedError,
        '3 dot-separated parts'
    );

    testThrows(
        'rejects single part',
        () => verifyToken('justonepart', keypair.publicKey),
        JwtMalformedError,
        '3 dot-separated parts'
    );

    testThrows(
        'rejects two parts',
        () => verifyToken('part.two', keypair.publicKey),
        JwtMalformedError,
        '3 dot-separated parts'
    );

    testThrows(
        'rejects four parts',
        () => verifyToken('one.two.three.four', keypair.publicKey),
        JwtMalformedError,
        '3 dot-separated parts'
    );

    testThrows(
        'rejects non-string input',
        () => verifyToken(12345, keypair.publicKey),
        JwtMalformedError,
        'must be a string'
    );

    testThrows(
        'rejects garbage in header',
        () => verifyToken('!!!!.eyJpc3MiOiJ4In0.sig', keypair.publicKey),
        JwtMalformedError
    );

    // ------------------------------------------------------------------------
    // Verification with JWK
    // ------------------------------------------------------------------------

    section('Verification with JWK format');

    const keyObject = crypto.createPublicKey(keypair.publicKey);
    const jwk = keyObject.export({ format: 'jwk' });

    const verifiedFromJwk = verifyToken(validToken, jwk);
    test('verifies using JWK', verifiedFromJwk.iss, 'test-vertical');

    // ------------------------------------------------------------------------
    // decodeUnverified
    // ------------------------------------------------------------------------

    section('decodeUnverified');

    const unverified = decodeUnverified(validToken);
    test('decodes header', unverified.header.alg, 'EdDSA');
    test('decodes payload iss', unverified.payload.iss, 'test-vertical');

    testThrows(
        'rejects malformed token',
        () => decodeUnverified('not.a.valid.jwt'),
        JwtMalformedError
    );

    // ------------------------------------------------------------------------
    // signToken input validation
    // ------------------------------------------------------------------------

    section('signToken input validation');

    testThrows(
        'requires claims object',
        () => signToken(null, keypair.privateKey, testKid),
        Error,
        'claims'
    );

    testThrows(
        'requires private key',
        () => signToken(baseClaims(), null, testKid),
        Error,
        'privateKeyPem'
    );

    testThrows(
        'requires kid',
        () => signToken(baseClaims(), keypair.privateKey, null),
        Error,
        'kid'
    );

    testThrows(
        'requires Ed25519 key',
        () => {
            const { privateKey: rsaPrivate } = crypto.generateKeyPairSync('rsa', {
                modulusLength: 2048,
                publicKeyEncoding: { type: 'spki', format: 'pem' },
                privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
            });
            signToken(baseClaims(), rsaPrivate, testKid);
        },
        Error,
        'Ed25519'
    );

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
// ============================================================================
// ThreadOS Core - Ed25519 Keypair Generator
// ============================================================================
//
// Generates Ed25519 keypairs in PEM format for development use. Each call
// produces a private/public pair, writes them to keys/<name>/private.pem and
// keys/<name>/public.pem, and refuses to overwrite existing keys (so we
// don't accidentally invalidate signatures by regenerating).
//
// Usage:
//   node scripts/generate-keys.js <name>
//
// Examples:
//   node scripts/generate-keys.js threados-core
//   node scripts/generate-keys.js test-vertical
//
// Bible reference:
//   Decision 18: Service-to-service auth via signed JWT
// ============================================================================

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const KEYS_DIR = path.join(__dirname, '..', 'keys');

// ----------------------------------------------------------------------------
// Color helpers (consistent with our other CLI tools)
// ----------------------------------------------------------------------------

const colors = {
    reset: '\x1b[0m',
    bold: '\x1b[1m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    red: '\x1b[31m',
    blue: '\x1b[34m',
    gray: '\x1b[90m',
};

function log(level, msg) {
    const prefix = {
        info: `${colors.gray}→${colors.reset}`,
        success: `${colors.green}✓${colors.reset}`,
        warn: `${colors.yellow}⚠${colors.reset}`,
        error: `${colors.red}✗${colors.reset}`,
    }[level];
    console.log(`${prefix} ${msg}`);
}

// ----------------------------------------------------------------------------
// Validate the requested name
// ----------------------------------------------------------------------------
//
// Names must be filesystem-safe and look like vertical slugs we'd use as
// JWT 'iss' claims: lowercase, alphanumeric, hyphens allowed.
// ----------------------------------------------------------------------------

const NAME_PATTERN = /^[a-z][a-z0-9-]{1,49}$/;

function validateName(name) {
    if (!name) {
        return 'name is required';
    }
    if (!NAME_PATTERN.test(name)) {
        return 'name must be lowercase alphanumeric (with hyphens allowed), starting with a letter, max 50 chars';
    }
    return null;
}

// ----------------------------------------------------------------------------
// Generate the keypair
// ----------------------------------------------------------------------------

function generateKeypair() {
    return crypto.generateKeyPairSync('ed25519', {
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
}

// ----------------------------------------------------------------------------
// Write keys to disk
// ----------------------------------------------------------------------------

function writeKeys(name, publicKey, privateKey) {
    const keyDir = path.join(KEYS_DIR, name);

    if (!fs.existsSync(KEYS_DIR)) {
        fs.mkdirSync(KEYS_DIR, { recursive: true });
    }

    if (fs.existsSync(keyDir)) {
        const privateExists = fs.existsSync(path.join(keyDir, 'private.pem'));
        const publicExists = fs.existsSync(path.join(keyDir, 'public.pem'));
        if (privateExists || publicExists) {
            throw new Error(
                `keys for "${name}" already exist at ${keyDir}. ` +
                `Delete the directory manually if you want to regenerate.`
            );
        }
    } else {
        fs.mkdirSync(keyDir, { recursive: true });
    }

    const privatePath = path.join(keyDir, 'private.pem');
    const publicPath = path.join(keyDir, 'public.pem');

    // Write private key with restrictive permissions (owner read/write only)
    fs.writeFileSync(privatePath, privateKey, { mode: 0o600 });
    fs.writeFileSync(publicPath, publicKey, { mode: 0o644 });

    return { privatePath, publicPath };
}

// ----------------------------------------------------------------------------
// Main
// ----------------------------------------------------------------------------

function main() {
    const name = process.argv[2];

    console.log(`${colors.bold}ThreadOS Core - Keypair Generator${colors.reset}\n`);

    const validationError = validateName(name);
    if (validationError) {
        log('error', validationError);
        console.log('');
        console.log(`${colors.gray}Usage:${colors.reset}`);
        console.log(`  node scripts/generate-keys.js <name>`);
        console.log('');
        console.log(`${colors.gray}Examples:${colors.reset}`);
        console.log(`  node scripts/generate-keys.js threados-core`);
        console.log(`  node scripts/generate-keys.js test-vertical`);
        process.exit(1);
    }

    log('info', `Generating Ed25519 keypair for "${name}"`);

    let publicKey, privateKey;
    try {
        ({ publicKey, privateKey } = generateKeypair());
    } catch (err) {
        log('error', `keypair generation failed: ${err.message}`);
        process.exit(1);
    }

    log('success', 'keypair generated');

    let paths;
    try {
        paths = writeKeys(name, publicKey, privateKey);
    } catch (err) {
        log('error', err.message);
        process.exit(1);
    }

    log('success', `private key written to ${path.relative(process.cwd(), paths.privatePath)} (mode 0600)`);
    log('success', `public key written to ${path.relative(process.cwd(), paths.publicPath)} (mode 0644)`);
    console.log('');
    console.log(`${colors.gray}Keys for "${name}" are ready.${colors.reset}`);
    console.log(`${colors.gray}The private key MUST NOT be shared. Public key is safe to distribute.${colors.reset}`);
}

main();
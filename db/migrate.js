// ============================================================================
// ThreadOS Core - Database Migration Runner
// ============================================================================
//
// Applies db/schema.sql to the configured PostgreSQL database.
//
// Safe to run multiple times: uses CREATE ... IF NOT EXISTS where possible,
// and tracks applied migrations in the schema_migrations table.
//
// Usage:
//   npm run migrate
// ============================================================================

require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { Client } = require('pg');

// ----------------------------------------------------------------------------
// Configuration
// ----------------------------------------------------------------------------

const config = {
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT, 10),
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
};

const SCHEMA_FILE = path.join(__dirname, 'schema.sql');

// ----------------------------------------------------------------------------
// Helpers for nicer output
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

const log = {
    section: (msg) => console.log(`\n${colors.bold}${colors.blue}━━ ${msg} ━━${colors.reset}`),
    step: (msg) => console.log(`${colors.gray}→${colors.reset} ${msg}`),
    success: (msg) => console.log(`${colors.green}✓${colors.reset} ${msg}`),
    warn: (msg) => console.log(`${colors.yellow}⚠${colors.reset} ${msg}`),
    error: (msg) => console.log(`${colors.red}✗${colors.reset} ${msg}`),
    info: (msg) => console.log(`  ${colors.gray}${msg}${colors.reset}`),
};

// ----------------------------------------------------------------------------
// Validate environment before doing anything
// ----------------------------------------------------------------------------

function validateEnvironment() {
    const required = ['DB_HOST', 'DB_PORT', 'DB_NAME', 'DB_USER', 'DB_PASSWORD'];
    const missing = required.filter(name => !process.env[name]);

    if (missing.length > 0) {
        log.error(`Missing required environment variables: ${missing.join(', ')}`);
        log.info('Copy .env.example to .env and fill in values, or set them in your shell.');
        process.exit(1);
    }

    if (!fs.existsSync(SCHEMA_FILE)) {
        log.error(`Schema file not found: ${SCHEMA_FILE}`);
        process.exit(1);
    }
}

// ----------------------------------------------------------------------------
// Main migration logic
// ----------------------------------------------------------------------------

async function runMigration() {
    console.log(`${colors.bold}ThreadOS Core Migration Runner${colors.reset}`);
    console.log(`${colors.gray}Database: ${config.user}@${config.host}:${config.port}/${config.database}${colors.reset}`);

    log.section('Pre-flight checks');
    validateEnvironment();
    log.success('Environment variables present');
    log.success(`Schema file found (${fs.statSync(SCHEMA_FILE).size} bytes)`);

    log.section('Connecting to database');
    const client = new Client(config);

    try {
        await client.connect();
        log.success('Connected to PostgreSQL');

        const versionResult = await client.query('SELECT version()');
        log.info(versionResult.rows[0].version.split(',')[0]);

    } catch (err) {
        log.error('Failed to connect to PostgreSQL');
        log.info(err.message);
        log.info('Is PostgreSQL running? Try: sudo service postgresql start');
        process.exit(1);
    }

    log.section('Applying schema');
    log.step('Reading schema.sql');
    const schemaSQL = fs.readFileSync(SCHEMA_FILE, 'utf8');
    log.info(`${schemaSQL.split('\n').length} lines, ${schemaSQL.length} bytes`);

    try {
        log.step('Executing schema');
        await client.query(schemaSQL);
        log.success('Schema applied successfully');
    } catch (err) {
        log.error('Failed to apply schema');
        log.info(err.message);
        if (err.position) {
            log.info(`Error position: character ${err.position}`);
        }
        await client.end();
        process.exit(1);
    }

    log.section('Verifying schema');

    try {
        // Check that expected tables exist
        const expectedTables = [
            'tenants',
            'identities',
            'consent_records',
            'event_type_registry',
            'events',
            'customers',
            'loyalty_transactions',
            'loyalty_balances',
            'integrations',
            'schema_migrations',
        ];

        const tableCheckResult = await client.query(`
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
            ORDER BY table_name
        `);

        const actualTables = tableCheckResult.rows.map(r => r.table_name);
        const missing = expectedTables.filter(t => !actualTables.includes(t));

        if (missing.length > 0) {
            log.error(`Missing expected tables: ${missing.join(', ')}`);
            await client.end();
            process.exit(1);
        }

        log.success(`All ${expectedTables.length} expected tables present`);
        log.info(actualTables.join(', '));

        // Check that helper functions exist
        const functionResult = await client.query(`
            SELECT routine_name 
            FROM information_schema.routines 
            WHERE routine_schema = 'public' AND routine_type = 'FUNCTION'
            ORDER BY routine_name
        `);

        const functions = functionResult.rows.map(r => r.routine_name);
        log.success(`${functions.length} helper functions installed`);
        log.info(functions.join(', '));

        // Test that hash_pii works
        const hashTest = await client.query(
            `SELECT hash_pii('test@example.com') AS hash`
        );
        if (hashTest.rows[0].hash && hashTest.rows[0].hash.length === 64) {
            log.success('hash_pii function verified (HMAC-SHA256 producing 64-char hex)');
        } else {
            log.warn('hash_pii function returned unexpected output');
        }

        // Check migration record
        const migrationResult = await client.query(
            `SELECT version, description, applied_at FROM schema_migrations ORDER BY applied_at`
        );
        log.success(`${migrationResult.rows.length} migration(s) recorded`);
        for (const row of migrationResult.rows) {
            log.info(`${row.version} - applied ${row.applied_at.toISOString()}`);
        }

    } catch (err) {
        log.error('Verification failed');
        log.info(err.message);
        await client.end();
        process.exit(1);
    }

    log.section('Done');
    log.success('ThreadOS Core database is ready');
    console.log('');

    await client.end();
}

// ----------------------------------------------------------------------------
// Run
// ----------------------------------------------------------------------------

runMigration().catch(err => {
    log.error('Unexpected error');
    console.error(err);
    process.exit(1);
});
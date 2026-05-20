// ============================================================================
// ThreadOS Core - Database Connection Pool
// ============================================================================
//
// Manages a pool of PostgreSQL connections shared across the application.
// 
// Why a pool: opening a new database connection per request would be slow
// (connection setup is non-trivial) and would quickly exhaust PostgreSQL's
// max_connections limit at any scale. A pool maintains a set of reusable
// connections so individual requests don't pay the setup cost.
//
// Usage:
//   const { query, withTransaction } = require('./db');
//   const result = await query('SELECT * FROM tenants WHERE id = $1', [tenantId]);
// ============================================================================

const { Pool } = require('pg');

// ----------------------------------------------------------------------------
// Pool configuration
// ----------------------------------------------------------------------------
//
// The pool is created lazily on first use rather than at module load. This
// makes the module easier to import in test setups that may override config.
// ----------------------------------------------------------------------------

let _pool = null;

function getPool() {
    if (_pool !== null) {
        return _pool;
    }

    _pool = new Pool({
        host: process.env.DB_HOST,
        port: parseInt(process.env.DB_PORT, 10),
        database: process.env.DB_NAME,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,

        // Pool sizing - reasonable defaults for development
        max: 20,                  // Max connections in pool
        idleTimeoutMillis: 30000, // Close idle connections after 30s
        connectionTimeoutMillis: 5000, // Fail fast if pool is exhausted

        // Statement timeout prevents runaway queries
        statement_timeout: 10000, // 10 seconds
    });

    // Log unexpected errors on idle pool clients. These are rare but worth
    // surfacing if they happen.
    _pool.on('error', (err) => {
        console.error('Unexpected error on idle database client:', err);
    });

    return _pool;
}

// ----------------------------------------------------------------------------
// Query helper
// ----------------------------------------------------------------------------
//
// Thin wrapper around pool.query that lets callers use a clean API:
//   const result = await query('SELECT * FROM x WHERE y = $1', [value]);
// 
// Returns the full result object from pg, which has .rows (array of objects),
// .rowCount, and other metadata.
// ----------------------------------------------------------------------------

async function query(text, params) {
    return getPool().query(text, params);
}

// ----------------------------------------------------------------------------
// Transaction helper
// ----------------------------------------------------------------------------
//
// Runs the provided function inside a database transaction. If the function
// throws, the transaction is rolled back. If it returns normally, the
// transaction is committed.
//
// Usage:
//   const result = await withTransaction(async (client) => {
//       await client.query('INSERT INTO ...');
//       await client.query('UPDATE ...');
//       return someValue;
//   });
//
// Important: inside the callback, use the provided client, not the pool's
// query() function. The client represents the single connection holding the
// transaction. Using a different connection would defeat the purpose.
// ----------------------------------------------------------------------------

async function withTransaction(fn) {
    const client = await getPool().connect();

    try {
        await client.query('BEGIN');
        const result = await fn(client);
        await client.query('COMMIT');
        return result;
    } catch (err) {
        await client.query('ROLLBACK');
        throw err;
    } finally {
        client.release();
    }
}

// ----------------------------------------------------------------------------
// Shutdown helper
// ----------------------------------------------------------------------------
//
// Closes all connections in the pool. Called during graceful server shutdown
// so that PostgreSQL doesn't see abrupt disconnects.
// ----------------------------------------------------------------------------

async function shutdown() {
    if (_pool !== null) {
        await _pool.end();
        _pool = null;
    }
}

// Internal: test helper to reset state between test runs.
function _resetPool() {
    _pool = null;
}

module.exports = {
    query,
    withTransaction,
    shutdown,
    _resetPool,
};
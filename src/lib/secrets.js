// ============================================================================
// ThreadOS Core - Secrets Access Layer
// ============================================================================
//
// Centralized access for all secrets used by ThreadOS Core. The rest of the
// codebase calls these functions instead of reading process.env directly.
//
// In development, secrets come from environment variables (loaded from .env
// via dotenv). In production, the implementation will be swapped to fetch
// from Google Secret Manager. Because callers go through these functions,
// the production migration changes only this file.
//
// Bible references:
//   Decision 1: PII hashing salt (HMAC-SHA256)
//   Decision 19: GCP-native security primitives (Secret Manager target)
// ============================================================================

// ----------------------------------------------------------------------------
// Cache
// ----------------------------------------------------------------------------
//
// Secrets are read lazily (on first request) and cached for the lifetime of
// the process. This means tests can override process.env before the first
// call, and we don't re-read on every operation.
// ----------------------------------------------------------------------------

const _cache = {};

function _resetCacheForTesting() {
    for (const key in _cache) {
        delete _cache[key];
    }
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

function _readEnv(name, { required = true } = {}) {
    const value = process.env[name];

    if (required && (!value || value.trim() === '')) {
        throw new Error(
            `Required environment variable ${name} is not set. ` +
            `In production this will come from Google Secret Manager; ` +
            `in development, set it in .env or your shell.`
        );
    }

    return value;
}

function _readEnvInt(name, defaultValue) {
    const value = process.env[name];
    if (!value) return defaultValue;
    const parsed = parseInt(value, 10);
    if (Number.isNaN(parsed)) {
        throw new Error(`Environment variable ${name} must be an integer; got "${value}"`);
    }
    return parsed;
}

// ----------------------------------------------------------------------------
// PII Hashing Salt
// ----------------------------------------------------------------------------
//
// Used by src/lib/hashing.js to produce HMAC-SHA256 hashes of PII values.
// Identity resolution depends on this salt being consistent across all hashes
// in a deployment - if it changes, existing hashed values can't be matched.
//
// In production: rotated periodically, stored in Secret Manager.
// In development: set in .env, never committed.
// ----------------------------------------------------------------------------

function getPiiHashSalt() {
    if (_cache.piiHashSalt !== undefined) {
        return _cache.piiHashSalt;
    }

    const salt = _readEnv('PII_HASH_SALT');
    _cache.piiHashSalt = salt;
    return salt;
}

// ----------------------------------------------------------------------------
// Database Configuration
// ----------------------------------------------------------------------------
//
// Connection parameters for the PostgreSQL database. In development these
// are local Codespace values. In production, the password (and possibly
// other fields) come from Secret Manager; the rest come from configuration.
//
// Returns an object suitable for passing to a pg Pool constructor.
// ----------------------------------------------------------------------------

function getDatabaseConfig() {
    if (_cache.databaseConfig !== undefined) {
        return _cache.databaseConfig;
    }

    const config = {
        host: _readEnv('DB_HOST'),
        port: _readEnvInt('DB_PORT', 5432),
        database: _readEnv('DB_NAME'),
        user: _readEnv('DB_USER'),
        password: _readEnv('DB_PASSWORD'),
    };

    _cache.databaseConfig = config;
    return config;
}

// ----------------------------------------------------------------------------
// Exports
// ----------------------------------------------------------------------------

module.exports = {
    getPiiHashSalt,
    getDatabaseConfig,
    // Internal: exposed only for tests that need to reset cached values
    // between cases (e.g., after overriding process.env).
    _resetCacheForTesting,
};
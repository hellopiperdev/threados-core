// ============================================================================
// ThreadOS Core - Express Server Setup
// ============================================================================
//
// Configures the Express application and registers routes. The server is
// created by createServer() rather than as a side effect of requiring this
// file, which makes it easier to test.
// ============================================================================

const express = require('express');
const identityRoutes = require('./routes/identity');

function createServer() {
    const app = express();

    // Suppress the X-Powered-By: Express header. Small information leak
    // that doesn't help anyone but us.
    app.disable('x-powered-by');

    // ------------------------------------------------------------------------
    // Global middleware
    // ------------------------------------------------------------------------
    
    // Parse JSON request bodies
    app.use(express.json({ limit: '100kb' }));
    
    // Tag every response with a service identifier (useful for debugging
    // when multiple services are involved)
    app.use((req, res, next) => {
        res.setHeader('X-Service', 'threados-core');
        next();
    });

    // ------------------------------------------------------------------------
    // Health check endpoint
    // ------------------------------------------------------------------------
    //
    // A simple endpoint that returns 200 OK if the server is running.
    // Used by load balancers, monitoring tools, and developers verifying
    // the server is alive.
    //
    // For now this just confirms the HTTP server is responding. In a later
    // session we'll add a /api/v1/health/deep that also checks database
    // connectivity.
    // ------------------------------------------------------------------------
    
    app.get('/api/v1/health', (req, res) => {
        res.json({
            status: 'ok',
            service: 'threados-core',
            timestamp: new Date().toISOString(),
        });
    });

    // ------------------------------------------------------------------------
    // Identity routes
    // ------------------------------------------------------------------------
    
    app.use('/api/v1/identity', identityRoutes);

    // ------------------------------------------------------------------------
    // JSON parse error handler
    // ------------------------------------------------------------------------
    //
    // When Express's JSON parser encounters malformed input, it throws an
    // error with type 'entity.parse.failed'. We handle that specifically and
    // return a 400 with a clear message - this is a client error, not a
    // server error, and the client deserves an actionable response.
    // ------------------------------------------------------------------------
    
    app.use((err, req, res, next) => {
        if (err.type === 'entity.parse.failed') {
            return res.status(400).json({
                error: {
                    code: 'invalid_json',
                    message: 'request body is not valid JSON',
                },
            });
        }

        if (err.type === 'entity.too.large') {
            return res.status(413).json({
                error: {
                    code: 'payload_too_large',
                    message: 'request body exceeds maximum size',
                },
            });
        }

        // Pass other errors to the catch-all handler below
        next(err);
    });

    // ------------------------------------------------------------------------
    // 404 handler
    // ------------------------------------------------------------------------
    // 
    // Catches requests to URLs that don't match any registered route.
    // Returns a structured JSON error rather than HTML so that API clients
    // can parse the response consistently.
    // ------------------------------------------------------------------------
    
    app.use((req, res) => {
        res.status(404).json({
            error: {
                code: 'not_found',
                message: `No route matches ${req.method} ${req.path}`,
            },
        });
    });

    // ------------------------------------------------------------------------
    // Generic error handler (catch-all for unexpected errors)
    // ------------------------------------------------------------------------
    //
    // Catches uncaught errors in any route handler. Logs them and returns a
    // generic 500 response. We don't expose internal error details to the
    // client (could leak sensitive info) but we do log them for debugging.
    // ------------------------------------------------------------------------
    
    app.use((err, req, res, next) => {
        console.error('Unhandled error:', err);
        res.status(500).json({
            error: {
                code: 'internal_error',
                message: 'An unexpected error occurred',
            },
        });
    });

    return app;
}

module.exports = { createServer };
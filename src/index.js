// ============================================================================
// ThreadOS Core - Application Entry Point
// ============================================================================
//
// This is the file that runs when we start the application. It's intentionally
// small: load environment variables, start the server, handle shutdown cleanly.
//
// All actual server logic lives in server.js so it can be tested in isolation.
// ============================================================================

require('dotenv').config();

const { createServer } = require('./server');

const PORT = parseInt(process.env.PORT || '3000', 10);

// ----------------------------------------------------------------------------
// Start the server
// ----------------------------------------------------------------------------

const app = createServer();

const server = app.listen(PORT, () => {
    console.log(`ThreadOS Core listening on port ${PORT}`);
    console.log(`Health check: http://localhost:${PORT}/api/v1/health`);
});

// ----------------------------------------------------------------------------
// Graceful shutdown
// ----------------------------------------------------------------------------
// 
// When the process is asked to stop (Ctrl+C, container shutdown, etc.), we
// stop accepting new connections, let existing requests finish, then exit.
// This prevents dropped requests during deployments.
// ----------------------------------------------------------------------------

function shutdown(signal) {
    console.log(`\nReceived ${signal}, shutting down gracefully...`);
    server.close((err) => {
        if (err) {
            console.error('Error during shutdown:', err);
            process.exit(1);
        }
        console.log('Server closed cleanly');
        process.exit(0);
    });
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
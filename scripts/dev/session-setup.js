// Manual testing helper for Step 6 Session 2 and future manual sessions.
// Sets up a test tenant, test vertical, baseline event registry entries,
// and prints a valid JWT we can paste into curl commands.
//
// Run from repo root: node scripts/dev/session-setup.js
// Keep the process running - the JWKS server it starts is what Core fetches
// keys from. Ctrl+C cleans up everything.

require('dotenv').config();

const { query, shutdown } = require('../../src/lib/db');
const authHelper = require('../../tests/helpers/auth');

const SLUG = '_manual_session_tenant';

async function main() {
    // Clean any prior leftovers
    await query('DELETE FROM tenants WHERE slug = $1', [SLUG]);

    // Create test tenant
    const tenantResult = await query(
        `INSERT INTO tenants (slug, display_name, vertical_module)
         VALUES ($1, 'Manual Session Test Tenant', 'test')
         RETURNING id`,
        [SLUG]
    );
    const tenantId = tenantResult.rows[0].id;

    // Set up auth context (vertical + local JWKS server + DB registration)
    // Use a longer TTL so we don't refetch constantly during the session.
    const authCtx = await authHelper.setupTestVertical({
        jwksCacheTtlSeconds: 3600,
    });

    // Seed baseline event registry entries for this tenant
    const baselineTypes = [
        { name: 'page_view', category: 'engagement' },
        { name: 'form_submitted', category: 'conversion' },
        { name: 'purchase', category: 'conversion' },
        { name: 'video_played', category: 'engagement' },
    ];

    for (const t of baselineTypes) {
        await query(
            `INSERT INTO event_type_registry
                (tenant_id, event_name, event_category, is_active)
             VALUES ($1, $2, $3, true)
             ON CONFLICT (tenant_id, event_name) DO NOTHING`,
            [tenantId, t.name, t.category]
        );
    }

    // Sign a token that's valid for an hour
    const token = authHelper.signTestToken(authCtx, { sub: tenantId });

    console.log('\n========================================');
    console.log('Manual session scaffolding READY');
    console.log('========================================\n');
    console.log('TENANT_ID:  ', tenantId);
    console.log('VERTICAL:   ', authCtx.slug);
    console.log('JWKS_URL:   ', authCtx.jwksUrl);
    console.log('\nPaste in another terminal:');
    console.log('export TENANT_ID=' + tenantId);
    console.log('export TOKEN=' + token);
    console.log('\nBaseline event registry entries:');
    baselineTypes.forEach(t => console.log('  -', t.name, '(' + t.category + ')'));
    console.log('\nKeep this process running. Ctrl+C cleans up.\n');

    // Trap shutdown for cleanup
    const cleanup = async (signal) => {
        console.log(`\n${signal} received, cleaning up...`);
        try {
            await authHelper.teardownTestVertical(authCtx);
            await query('DELETE FROM tenants WHERE slug = $1', [SLUG]);
            await shutdown();
            console.log('Cleaned up.');
            process.exit(0);
        } catch (err) {
            console.error('Cleanup error:', err.message);
            process.exit(1);
        }
    };
    process.on('SIGINT', () => cleanup('SIGINT'));
    process.on('SIGTERM', () => cleanup('SIGTERM'));

    // Block forever
    await new Promise(() => {});
}

main().catch(err => {
    console.error('Setup failed:', err);
    process.exit(1);
});

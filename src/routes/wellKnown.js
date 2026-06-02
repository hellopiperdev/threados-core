// ============================================================================
// ThreadOS Core - Well-Known Endpoints
// ============================================================================
//
// RFC 8615 defines /.well-known/ as a standard URL path for service
// metadata. Our JWKS document lives at /.well-known/jwks.json - the
// industry-standard location for public-key discovery.
//
// In production, anyone wanting to verify signatures from Core would fetch
// this endpoint. Today, this endpoint mostly exists so we can prove the
// JWKS-serving logic works before depending on it in Session 4.
//
// Bible reference:
//   Decision 18: Service-to-service auth via signed JWT
// ============================================================================

const express = require('express');
const { getCoreJwks } = require('../lib/jwks');

const router = express.Router();

// ----------------------------------------------------------------------------
// GET /.well-known/jwks.json
// ----------------------------------------------------------------------------
//
// Returns Core's JWKS document. The response includes appropriate caching
// hints so clients can cache the document client-side as well.
//
// Response (200):
//   {
//     "keys": [
//       {
//         "kty": "OKP",
//         "crv": "Ed25519",
//         "x": "<base64url public key>",
//         "kid": "<key id>",
//         "alg": "EdDSA",
//         "use": "sig"
//       }
//     ]
//   }
// ----------------------------------------------------------------------------

router.get('/jwks.json', (req, res, next) => {
    try {
        const jwks = getCoreJwks();

        // Cache for 1 hour by default. Clients should respect this.
        res.setHeader('Cache-Control', 'public, max-age=3600');

        res.json(jwks);
    } catch (err) {
        next(err);
    }
});

module.exports = router;
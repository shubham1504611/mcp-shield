/**
 * Standalone Ed25519 Cryptographic Attestation Verifier
 * Verifies signatures against the public key from the gateway
 */

const crypto = require('crypto');
const https = require('https');

function fetchRemoteJwks(jwksUrl = 'https://mcp-shield-gateway-core.vercel.app/.well-known/jwks.json') {
  return new Promise((resolve, reject) => {
    https.get(jwksUrl, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          resolve(parsed.keys ? parsed.keys[0] : parsed);
        } catch (err) {
          reject(new Error(`Failed to parse JWKS: ${err.message}`));
        }
      });
    }).on('error', reject);
  });
}

function verifyAttestationSignature({ tool, payload, nonce, timestamp, policyVersion = '2.5.0', signature, publicKeyPem }) {
  if (!signature) {
    return { valid: false, error: 'MISSING_SIGNATURE' };
  }

  const payloadStr = typeof payload === 'string' ? payload : JSON.stringify(payload || {});
  const canonical = `${tool}:${payloadStr}:${nonce}:${timestamp}:${policyVersion}`;
  const hash = crypto.createHash('sha256').update(canonical).digest();

  try {
    const isVerified = crypto.verify(
      null,
      hash,
      publicKeyPem,
      Buffer.from(signature, 'hex')
    );
    return {
      valid: isVerified,
      canonical,
      algorithm: 'Ed25519'
    };
  } catch (err) {
    return { valid: false, error: err.message };
  }
}

module.exports = {
  fetchRemoteJwks,
  verifyAttestationSignature
};

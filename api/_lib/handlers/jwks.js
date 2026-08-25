const crypto = require('crypto');
const { PUBLIC_KEY } = require('../waf');

function getJwk() {
  try {
    const pubKeyObj = crypto.createPublicKey(PUBLIC_KEY);
    const jwk = pubKeyObj.export({ format: 'jwk' });
    return {
      kty: jwk.kty || 'OKP',
      crv: jwk.crv || 'Ed25519',
      use: 'sig',
      alg: 'EdDSA',
      kid: 'mcp-shield-enclave-v2.5',
      x: jwk.x
    };
  } catch (_) {
    // Fallback manual extract
    const cleanBase64 = PUBLIC_KEY.replace(/-----BEGIN PUBLIC KEY-----|\r|\n|-----END PUBLIC KEY-----|\s+/g, '');
    const buf = Buffer.from(cleanBase64, 'base64');
    const rawX = buf.subarray(buf.length - 32).toString('base64url');
    return {
      kty: 'OKP',
      crv: 'Ed25519',
      use: 'sig',
      alg: 'EdDSA',
      kid: 'mcp-shield-enclave-v2.5',
      x: rawX
    };
  }
}

module.exports = async (req, res) => {
  if (typeof res.status !== 'function') {
    res.status = (code) => { res.statusCode = code; return res; };
  }
  if (typeof res.json !== 'function') {
    res.json = (data) => {
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.end(JSON.stringify(data));
      return res;
    };
  }

  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Cache-Control', 'public, max-age=86400');

  const jwk = getJwk();
  return res.status(200).json({
    keys: [jwk]
  });
};

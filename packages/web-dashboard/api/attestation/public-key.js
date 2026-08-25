const { PUBLIC_KEY } = require('../lib/waf');

const ALLOWED_ORIGINS = [
  'https://mcp-shield-gateway-core.vercel.app',
  'http://localhost:3000',
  'http://localhost:8080',
  'http://127.0.0.1:3000',
  'http://127.0.0.1:8080'
];

module.exports = async (req, res) => {
  const origin = req.headers['origin'];
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else {
    res.setHeader('Access-Control-Allow-Origin', 'https://mcp-shield-gateway-core.vercel.app');
  }

  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  return res.status(200).json({
    algorithm: 'Ed25519',
    format: 'SPKI_PEM',
    publicKey: PUBLIC_KEY,
    canonicalFormatSpecification: '${toolName}:${JSON.stringify(sanitizedPayload)}:${nonce}:${timestamp}:${policyVersion}',
    policyVersion: '2.5.0',
    purpose: 'Hardware-grade deterministic attestation of pre-screened Model Context Protocol tool requests'
  });
};

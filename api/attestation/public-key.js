const { PUBLIC_KEY } = require('../lib/waf');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  return res.status(200).json({
    algorithm: 'Ed25519',
    format: 'SPKI_PEM',
    publicKey: PUBLIC_KEY,
    canonicalFormatSpecification: '${toolName}:${JSON.stringify(sanitizedPayload)}',
    purpose: 'Hardware-grade deterministic attestation of pre-screened Model Context Protocol tool requests'
  });
};

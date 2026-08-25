const evaluateHandler = require('./_lib/handlers/evaluate');
const mcpHandler = require('./_lib/handlers/mcp');
const keysHandler = require('./_lib/handlers/keys');
const metricsHandler = require('./_lib/handlers/metrics');
const logsHandler = require('./_lib/handlers/logs');
const attestationHandler = require('./_lib/handlers/attestation');
const registryHandler = require('./_lib/handlers/registry');
const healthHandler = require('./_lib/handlers/health');
const jwksHandler = require('./_lib/handlers/jwks');
const dsrHandler = require('./_lib/handlers/dsr');

const ALLOWED_ORIGINS = [
  'https://mcp-shield-gateway-core.vercel.app',
  'http://localhost:3000',
  'http://localhost:8080',
  'http://127.0.0.1:3000',
  'http://127.0.0.1:8080'
];

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

  const origin = req.headers['origin'];
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else {
    res.setHeader('Access-Control-Allow-Origin', 'https://mcp-shield-gateway-core.vercel.app');
  }

  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Mcp-Method, Mcp-Name, X-API-Key, X-Admin-Secret, X-MCP-Approval-Token, X-Request-Id');
  const crypto = require('crypto');
  const requestId = req.headers['x-request-id'] || `req_${crypto.randomBytes(8).toString('hex')}`;
  res.setHeader('X-Request-Id', requestId);
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const rawUrl = req.url || '/';
  const pathname = rawUrl.split('?')[0].replace(/\/+$/, '') || '/';

  // 1. Tool Call Evaluation
  if (pathname.endsWith('/evaluate')) {
    return evaluateHandler(req, res);
  }

  // 2. MCP JSON-RPC Gateway
  if (pathname.endsWith('/mcp') || pathname === '/v1/mcp') {
    return mcpHandler(req, res);
  }

  // 3. API Key Generation & Rotation
  if (pathname.endsWith('/keys/generate') || pathname.endsWith('/keys/rotate')) {
    return keysHandler(req, res);
  }

  // 4. Telemetry Metrics
  if (pathname.endsWith('/metrics') || pathname.endsWith('/telemetry/metrics')) {
    return metricsHandler(req, res);
  }

  // 5. Audit Feed Logs
  if (pathname.endsWith('/logs') || pathname.endsWith('/audit/logs')) {
    return logsHandler(req, res);
  }

  // 6. Cryptographic Attestation Public Key & JWKS
  if (pathname.endsWith('/jwks.json') || pathname.endsWith('/attestation/jwks') || pathname.includes('.well-known/jwks.json')) {
    return jwksHandler(req, res);
  }
  if (pathname.endsWith('/attestation/public-key') || pathname.endsWith('/attestation/key')) {
    return attestationHandler(req, res);
  }

  // 7. Protected Tool Registry
  if (pathname.endsWith('/registry') || pathname.endsWith('/registry/tools')) {
    return registryHandler(req, res);
  }

  // 8. GDPR & CCPA Data Privacy Rights
  if (pathname.includes('/account/export') || pathname.includes('/account/delete')) {
    return dsrHandler(req, res);
  }

  // 9. Health Check / Status
  if (pathname.endsWith('/health') || pathname.endsWith('/healthz') || pathname.includes('readyz')) {
    return healthHandler(req, res);
  }

  // Root / Status endpoint
  return res.status(200).json({
    status: 'ONLINE',
    service: 'MCP Shield Platform API',
    version: '2.5.0',
    license: 'MIT',
    enclave: 'Deterministic Ed25519 Cryptographic Enclave',
    endpoints: [
      '/api/evaluate',
      '/api/keys/generate',
      '/api/telemetry/metrics',
      '/api/audit/logs',
      '/api/attestation/public-key',
      '/api/health',
      '/.well-known/jwks.json',
      '/v1/mcp'
    ]
  });
};

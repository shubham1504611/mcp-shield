const crypto = require('crypto');
const { getAllTools } = require('./lib/tools');

// In-memory key & telemetry store
global.__MCP_API_KEYS__ = global.__MCP_API_KEYS__ || new Map();
global.__MCP_AUDIT_LOGS__ = global.__MCP_AUDIT_LOGS__ || [];
global.__MCP_METRICS__ = global.__MCP_METRICS__ || {
  totalCalls: 0,
  blockedThreats: 0,
  latencies: []
};

module.exports = async (req, res) => {
  try {
    const origin = req.headers['origin'] || '*';
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

    if (req.method === 'OPTIONS') {
      return res.status(200).end();
    }

    const url = req.url || '';

    // 1. Healthcheck & readiness
    if (url.includes('healthz') || url.includes('readyz')) {
      return res.status(200).json({ 
        status: 'HEALTHY', 
        timestamp: new Date().toISOString(), 
        service: 'MCP Shield Open-Source Gateway',
        enclave: 'Ed25519 Cryptographic Verification'
      });
    }

    // 2. Verified Tool Registry Endpoint
    if (url.includes('registry') || url.includes('v1/registry/tools')) {
      const tools = getAllTools();
      return res.status(200).json({
        count: tools.length,
        tools
      });
    }

    return res.status(200).json({ 
      status: 'ONLINE', 
      service: 'MCP Shield Platform API',
      version: '2.5.0',
      license: 'MIT',
      endpoints: [
        '/api/evaluate',
        '/api/keys/generate',
        '/api/registry',
        '/api/telemetry/metrics',
        '/api/audit/logs',
        '/api/attestation/public-key',
        '/v1/mcp'
      ]
    });
  } catch (err) {
    console.error('Serverless Function Error:', err);
    return res.status(500).json({ error: 'Internal Server Error', message: err.message });
  }
};

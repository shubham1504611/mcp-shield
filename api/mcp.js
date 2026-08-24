const { SecurityWaf, PUBLIC_KEY } = require('../packages/gateway-core/src/security/waf');

const waf = new SecurityWaf();

module.exports = async (req, res) => {
  try {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Mcp-Method, Mcp-Name');

    if (req.method === 'OPTIONS') {
      res.status(200).end();
      return;
    }

    const url = req.url || '';

    // Healthcheck
    if (req.method === 'GET' || url.includes('healthz') || url.includes('readyz')) {
      res.status(200).json({
        status: 'HEALTHY',
        service: 'MCP Shield Gateway Core',
        engine: 'Zero-Trust 4-Phase Hardened WAF',
        enclave: 'Deterministic Ed25519 Enclave',
        p99_latency: '<1.5ms',
        timestamp: new Date().toISOString()
      });
      return;
    }

    // Process MCP Tool Call (POST)
    let body = req.body;
    if (typeof body === 'string') {
      try { body = JSON.parse(body); } catch (_) { body = {}; }
    }
    if (!body || typeof body !== 'object') {
      body = {};
    }

    const toolName = req.headers['mcp-name'] || body.params?.name || body.method || 'unknown_tool';
    const params = body.params?.arguments || body.params || {};

    const check = waf.inspectToolCall(toolName, params);

    if (!check.isSafe) {
      res.status(200).json({
        jsonrpc: '2.0',
        id: body.id || null,
        error: {
          code: -32001,
          message: `Security Policy Violation: ${check.reason} (Rule: ${check.rule})`,
          data: {
            trace_id: check.traceId || null,
            action_taken: 'BLOCKED_BY_WAF',
            timestamp: new Date().toISOString()
          }
        }
      });
      return;
    }

    res.setHeader('X-MCP-Signature', check.signature);
    res.setHeader('X-MCP-Trace-ID', check.traceId);
    res.setHeader('X-MCP-Public-Key', PUBLIC_KEY);

    res.status(200).json({
      jsonrpc: '2.0',
      id: body.id || 1,
      result: {
        status: 'AUTHENTICATED_AND_SIGNED',
        trace_id: check.traceId,
        attestation: check.signature,
        publicKey: PUBLIC_KEY,
        message: 'Payload passed hardened 4-phase zero-trust inspection'
      }
    });
  } catch (err) {
    res.status(500).json({
      error: 'MCP Gateway Error',
      message: err.message
    });
  }
};

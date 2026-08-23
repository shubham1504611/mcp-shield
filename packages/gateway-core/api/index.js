const { McpGatewayProxy } = require('../src/proxy');

const gateway = new McpGatewayProxy();

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Mcp-Method, Mcp-Name');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const url = req.url || '';

  // 1. Healthchecks
  if (url.includes('healthz') || url.includes('readyz')) {
    return res.status(200).json({
      status: 'HEALTHY',
      service: 'MCP Shield Gateway Core',
      engine: 'Zero-Trust 4-Phase WAF',
      enclave: 'Ed25519 Hardware Attested',
      timestamp: new Date().toISOString()
    });
  }

  // 2. Streamable MCP JSON-RPC Proxy on /v1/mcp or root POST
  if (url.includes('/v1/mcp') || req.method === 'POST') {
    return gateway.handleRequest(req, res);
  }

  // 3. Fallback Status
  return res.status(200).json({
    status: 'ONLINE',
    service: 'MCP Shield Gateway Core',
    endpoint: '/v1/mcp',
    docs: 'https://github.com/shubham1504611/mcp-shield'
  });
};

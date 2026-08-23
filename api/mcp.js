const { McpGatewayProxy } = require('../packages/gateway-core/src/proxy');

const gateway = new McpGatewayProxy();

module.exports = async (req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Mcp-Method, Mcp-Name');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  return gateway.handleRequest(req, res);
};

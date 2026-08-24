/**
 * Standalone HTTP Server for Gateway Core
 */

const http = require('http');
const { McpGatewayProxy } = require('./proxy');
const { TunnelCoordinator } = require('./tunnel/coordinator');
const { getAllTools, getToolById, getToolsByCategory } = require('./registry/tools');

function createGatewayServer(options = {}) {
  const proxy = new McpGatewayProxy(options);
  const coordinator = new TunnelCoordinator(options);

  const server = http.createServer((req, res) => {
    // Enable CORS for API & Dashboard
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Mcp-Method, Mcp-Name');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      return res.end();
    }

    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const pathname = url.pathname;

    // Health and readiness probes
    if (req.method === 'GET' && pathname === '/healthz') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ status: 'HEALTHY', timestamp: new Date().toISOString() }));
    }

    if (req.method === 'GET' && pathname === '/readyz') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ status: 'READY', uptime: process.uptime() }));
    }

    // Community Tool Registry Endpoints
    if (req.method === 'GET' && pathname === '/v1/registry/tools') {
      const category = url.searchParams.get('category');
      const tools = category ? getToolsByCategory(category) : getAllTools();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ count: tools.length, tools }));
    }

    if (req.method === 'GET' && pathname.startsWith('/v1/registry/tools/')) {
      const toolId = pathname.replace('/v1/registry/tools/', '').trim();
      const tool = getToolById(toolId);
      if (!tool) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: `Tool '${toolId}' not found in registry` }));
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(tool));
    }

    // Tunnel active sessions inspection
    if (req.method === 'GET' && pathname === '/v1/tunnels') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ activeTunnels: coordinator.listActiveTunnels() }));
    }

    // Telemetry logs endpoint for web dashboard
    if (req.method === 'GET' && pathname === '/v1/audit/logs') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ logs: proxy.auditLogs.slice(-50) }));
    }

    // Streamable HTTP MCP Endpoint
    if (req.method === 'POST' && (pathname === '/v1/mcp' || pathname === '/')) {
      const chunks = [];
      req.on('data', chunk => chunks.push(chunk));
      req.on('end', () => {
        const bodyBuffer = Buffer.concat(chunks);
        proxy.handleMcpRequest(req, res, bodyBuffer);
      });
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Endpoint not found' }));
  });

  return { server, proxy, coordinator };
}

module.exports = { createGatewayServer };

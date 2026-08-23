/**
 * Standalone HTTP Server for Gateway Core
 */

const http = require('http');
const { McpGatewayProxy } = require('./proxy');

function createGatewayServer(options = {}) {
  const proxy = new McpGatewayProxy(options);

  const server = http.createServer((req, res) => {
    // Health and readiness probes
    if (req.method === 'GET' && req.url === '/healthz') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ status: 'HEALTHY', timestamp: new Date().toISOString() }));
    }

    if (req.method === 'GET' && req.url === '/readyz') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ status: 'READY', uptime: process.uptime() }));
    }

    // Telemetry logs endpoint for web dashboard
    if (req.method === 'GET' && req.url === '/v1/audit/logs') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ logs: proxy.auditLogs.slice(-50) }));
    }

    // Streamable HTTP MCP Endpoint
    if (req.method === 'POST' && (req.url === '/v1/mcp' || req.url === '/')) {
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

  return { server, proxy };
}

module.exports = { createGatewayServer };

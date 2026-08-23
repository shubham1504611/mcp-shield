/**
 * Unified Web Dashboard & Gateway HTTP Server
 * Serves the interactive control plane, API routes, and /v1/mcp Gateway Proxy
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const { generateApiKey } = require('./api/keys');
const { calculateDashboardMetrics } = require('./api/telemetry');
const { handleDodoWebhook } = require('./api/webhooks');
const { McpGatewayProxy } = require('../../gateway-core/src/proxy');

function startDashboardServer(port = 3000, callback) {
  const publicDir = path.join(__dirname, 'public');
  const gateway = new McpGatewayProxy();

  const server = http.createServer((req, res) => {
    // 1. Healthcheck & readiness probes
    if (req.method === 'GET' && (req.url === '/healthz' || req.url === '/readyz')) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ status: 'HEALTHY', timestamp: new Date().toISOString() }));
    }

    // 2. Gateway Core Proxy on /v1/mcp
    if (req.url === '/v1/mcp') {
      return gateway.handleRequest(req, res);
    }

    // 3. API: Generate new API key
    if (req.method === 'POST' && req.url === '/api/keys/generate') {
      const keyData = generateApiKey('org_demo_123', 'Web UI Generated Key');
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(keyData));
    }

    // 4. API: Telemetry metrics
    if (req.method === 'GET' && req.url === '/api/telemetry/metrics') {
      const metrics = calculateDashboardMetrics(gateway.auditLogs.length > 0 ? gateway.auditLogs : [
        { isBlocked: false, latencyMs: 2 },
        { isBlocked: true, latencyMs: 1 }
      ]);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(metrics));
    }

    // 5. API: Dodo Payments Webhook
    if (req.method === 'POST' && req.url === '/api/webhooks/dodo') {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        try {
          const payload = JSON.parse(body || '{}');
          const signature = req.headers['x-dodo-signature'] || '';
          const result = handleDodoWebhook(payload, signature, process.env.DODO_WEBHOOK_SECRET || 'whsec_demo_secret');
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(result));
        } catch (err) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Malformed webhook payload' }));
        }
      });
      return;
    }

    // 6. Static Assets Routing for Web Dashboard
    let filePath = path.join(publicDir, req.url === '/' ? 'index.html' : req.url);
    const ext = path.extname(filePath);

    const contentTypes = {
      '.html': 'text/html',
      '.css': 'text/css',
      '.js': 'application/javascript',
      '.json': 'application/json',
      '.png': 'image/png',
      '.svg': 'image/svg+xml'
    };

    const contentType = contentTypes[ext] || 'text/plain';

    fs.readFile(filePath, (err, content) => {
      if (err) {
        if (err.code === 'ENOENT') {
          res.writeHead(404, { 'Content-Type': 'text/plain' });
          res.end('404 Not Found');
        } else {
          res.writeHead(500, { 'Content-Type': 'text/plain' });
          res.end('500 Internal Server Error');
        }
      } else {
        res.writeHead(200, { 'Content-Type': contentType });
        res.end(content);
      }
    });
  });

  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      const fallbackPort = port + 1;
      console.log(`Port ${port} in use, trying http://localhost:${fallbackPort}...`);
      startDashboardServer(fallbackPort, callback);
    } else {
      console.error('Server error:', err);
    }
  });

  server.listen(port, () => {
    if (callback) callback(port);
  });

  return server;
}

// Standalone execution check
if (require.main === module) {
  const initialPort = Number(process.env.PORT) || 3000;
  startDashboardServer(initialPort, (port) => {
    console.log(`\n🚀 MCP Shield Unified Gateway & Dashboard running at: http://localhost:${port}\n`);
  });
}

module.exports = { startDashboardServer };

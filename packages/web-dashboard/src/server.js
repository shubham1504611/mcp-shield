/**
 * Web Dashboard HTTP Server
 * Serves the interactive control plane on http://localhost:3000
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const { generateApiKey } = require('./api/keys');
const { calculateDashboardMetrics } = require('./api/telemetry');

function startDashboardServer(port = 3000, callback) {
  const publicDir = path.join(__dirname, 'public');

  const server = http.createServer((req, res) => {
    // API: Generate new API key
    if (req.method === 'POST' && req.url === '/api/keys/generate') {
      const keyData = generateApiKey('org_demo_123', 'Web UI Generated Key');
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(keyData));
    }

    // API: Telemetry metrics
    if (req.method === 'GET' && req.url === '/api/telemetry/metrics') {
      const metrics = calculateDashboardMetrics([
        { isBlocked: false, latencyMs: 2 },
        { isBlocked: true, latencyMs: 1 }
      ]);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(metrics));
    }

    // Static Assets Routing
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
    console.log(`\n🚀 MCP Shield Institutional Web Dashboard running at: http://localhost:${port}\n`);
  });
}

module.exports = { startDashboardServer };

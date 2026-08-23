/**
 * Local Shield Daemon Runner
 * Starts zero-config local loopback proxy on 127.0.0.1:8080 with live terminal HUD.
 */

const http = require('http');
const { SecurityWaf } = require('../../gateway-core/src/security/waf');
const { createSecurityBlockResponse } = require('../../gateway-core/src/security/error-protocol');

class LocalShieldRunner {
  constructor(options = {}) {
    this.port = options.port || 8080;
    this.waf = new SecurityWaf(options.wafConfig || {});
    this.logs = [];
    this.blockedCount = 0;
    this.totalCalls = 0;
  }

  start(callback) {
    this.server = http.createServer((req, res) => {
      // Live HUD API for local browser dashboard
      if (req.method === 'GET' && req.url === '/live') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          status: 'ACTIVE',
          port: this.port,
          totalCalls: this.totalCalls,
          blockedCount: this.blockedCount,
          recentLogs: this.logs.slice(-20)
        }));
      }

      // MCP Tool Traffic Proxy
      if (req.method === 'POST') {
        const chunks = [];
        req.on('data', chunk => chunks.push(chunk));
        req.on('end', () => {
          this.totalCalls++;
          const startTime = Date.now();
          let body;

          try {
            body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          } catch (_) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Invalid JSON' } }));
          }

          const toolName = req.headers['mcp-name'] || body.params?.name || 'unknown_tool';
          const wafResult = this.waf.inspectToolCall(toolName, body.params?.arguments || {});

          if (!wafResult.isSafe) {
            this.blockedCount++;
            const logEntry = {
              tool: toolName,
              status: 'BLOCKED',
              rule: wafResult.rule,
              reason: wafResult.reason,
              latencyMs: Date.now() - startTime,
              timestamp: new Date().toLocaleTimeString()
            };
            this.logs.push(logEntry);

            res.writeHead(200, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify(createSecurityBlockResponse(body.id || 1, wafResult)));
          }

          // Safe execution simulation / pass-through
          const logEntry = {
            tool: toolName,
            status: 'SECURE_PASS',
            latencyMs: Date.now() - startTime,
            timestamp: new Date().toLocaleTimeString()
          };
          this.logs.push(logEntry);

          res.writeHead(200, {
            'Content-Type': 'application/json',
            'X-MCP-Signature': wafResult.signature,
            'X-MCP-Trace-ID': wafResult.traceId
          });

          res.end(JSON.stringify({
            jsonrpc: '2.0',
            id: body.id || 1,
            result: {
              content: [
                { type: 'text', text: `[MCP-SHIELD LOCAL]: Verified secure execution for '${toolName}'.` }
              ]
            }
          }));
        });
        return;
      }

      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`
        <html>
          <body style="background:#09090b;color:#f4f4f5;font-family:sans-serif;padding:2rem;">
            <h1>🛡️ MCP Shield Local HUD</h1>
            <p>Status: <span style="color:#22c55e;">● Active Protection</span> (Port ${this.port})</p>
            <p>Total Calls: <b>${this.totalCalls}</b> | Blocked Threats: <b style="color:#ef4444;">${this.blockedCount}</b></p>
          </body>
        </html>
      `);
    });

    this.server.listen(this.port, '127.0.0.1', () => {
      if (callback) callback(this.port);
    });
  }

  stop(callback) {
    if (this.server) {
      this.server.close(callback);
    }
  }
}

module.exports = { LocalShieldRunner };

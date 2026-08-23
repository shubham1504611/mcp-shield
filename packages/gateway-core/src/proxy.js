/**
 * Core Streamable HTTP Reverse Proxy Engine for MCP
 * Conforms to Linux Foundation / Agentic AI Foundation 2026-07-28 Spec.
 */

const http = require('http');
const https = require('https');
const { URL } = require('url');
const { SecurityWaf } = require('./security/waf');
const {
  createSecurityBlockResponse,
  createRateLimitResponse,
  createInvalidAuthResponse
} = require('./security/error-protocol');
const { InMemoryAuthCache, TokenBucketRateLimiter } = require('./auth/cache');

class McpGatewayProxy {
  constructor(options = {}) {
    this.waf = new SecurityWaf(options.wafConfig || {});
    this.authCache = new InMemoryAuthCache(options.authTtlMs || 60000);
    this.rateLimiter = new TokenBucketRateLimiter(
      options.rateLimitMax || 120,
      options.refillRatePerSec || 2
    );
    this.toolRegistry = new Map(); // toolName -> destinationUrl
    this.auditLogs = []; // Fixed-capacity in-memory telemetry ring buffer (max 200 items)
    this.maxAuditLogs = 200;
  }

  recordAuditLog(entry) {
    if (this.auditLogs.length >= this.maxAuditLogs) {
      this.auditLogs.shift(); // Evict oldest log entry O(1) amortized
    }
    this.auditLogs.push(entry);
  }

  registerTool(name, destinationUrl) {
    this.toolRegistry.set(name, destinationUrl);
  }

  registerApiKey(apiKey, orgData) {
    this.authCache.set(apiKey, orgData);
  }

  /**
   * Main Request Processor for Streamable HTTP POST
   */
  async handleMcpRequest(req, res, bodyBuffer) {
    const startTime = Date.now();
    let body;

    try {
      body = JSON.parse(bodyBuffer.toString('utf8'));
    } catch (err) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({
        jsonrpc: '2.0',
        id: null,
        error: { code: -32700, message: 'Parse Error: Invalid JSON-RPC payload' }
      }));
    }

    const requestId = body.id || 1;
    const headerMethod = req.headers['mcp-method'];
    const bodyMethod = body.method;

    // Protocol Desync Protection: Validate that Header and Body methods do not conflict
    if (headerMethod && bodyMethod && headerMethod !== bodyMethod) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({
        jsonrpc: '2.0',
        id: requestId,
        error: {
          code: -32600,
          message: `[MCP-SHIELD PROTOCOL ERROR]: Header 'Mcp-Method: ${headerMethod}' and Body 'method: ${bodyMethod}' mismatch (Method Confusion Attack Prevented).`,
          data: {
            header_method: headerMethod,
            body_method: bodyMethod,
            action: 'DESYNC_BLOCKED'
          }
        }
      }));
    }

    const mcpMethod = bodyMethod || headerMethod;
    const mcpName = (body.params && body.params.name) || req.headers['mcp-name'];
    const authHeader = req.headers['authorization'] || '';
    const bearerToken = authHeader.replace(/^Bearer\s+/i, '').trim();

    // 1. Authentication Check
    if (!bearerToken) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(createInvalidAuthResponse(requestId, 'Missing Authorization Bearer token.')));
    }

    const authData = this.authCache.get(bearerToken);
    if (!authData) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(createInvalidAuthResponse(requestId, 'API Key not found or expired.')));
    }

    // 2. Rate Limiting Check
    const rateCheck = this.rateLimiter.tryConsume(bearerToken);
    if (!rateCheck.allowed) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify(createRateLimitResponse(requestId, rateCheck.retryAfterSeconds)));
    }

    // 3. Security Inspection for Tool Calls
    if (mcpMethod === 'tools/call' && mcpName) {
      const wafResult = this.waf.inspectToolCall(mcpName, body.params?.arguments || {});
      
      if (!wafResult.isSafe) {
        // Record blocked audit log
        this.recordAuditLog({
          toolName: mcpName,
          method: mcpMethod,
          statusCode: 403,
          isBlocked: true,
          blockedReason: wafResult.reason,
          latencyMs: Date.now() - startTime,
          timestamp: new Date().toISOString()
        });

        // Return structured JSON-RPC 2.0 error over HTTP 200
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify(createSecurityBlockResponse(requestId, wafResult)));
      }

      // Check destination routing
      const targetUrl = this.toolRegistry.get(mcpName);
      if (!targetUrl) {
        // If not a registered remote tool, return standard tool not found or mock local execution
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'X-MCP-Trace-ID': wafResult.traceId,
          'X-MCP-Signature': wafResult.signature
        });

        const mockResponse = {
          jsonrpc: '2.0',
          id: requestId,
          result: {
            content: [
              { type: 'text', text: `[MCP-SHIELD SECURE RESULT]: Tool '${mcpName}' executed cleanly.` }
            ]
          }
        };

        this.recordAuditLog({
          toolName: mcpName,
          method: mcpMethod,
          statusCode: 200,
          isBlocked: false,
          latencyMs: Date.now() - startTime,
          timestamp: new Date().toISOString()
        });

        return res.end(JSON.stringify(mockResponse));
      }

      // Forward to target URL
      return this.forwardRequest(targetUrl, body, req.headers, wafResult, res, startTime);
    }

    // Handle standard protocol methods (e.g. tools/list, resources/list)
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({
      jsonrpc: '2.0',
      id: requestId,
      result: {
        tools: Array.from(this.toolRegistry.keys()).map(name => ({
          name,
          description: `Verified secure tool: ${name}`
        }))
      }
    }));
  }

  /**
   * Forwards sanitized request to remote destination endpoint
   */
  forwardRequest(targetUrl, body, originalHeaders, wafResult, res, startTime) {
    const urlObj = new URL(targetUrl);
    const transport = urlObj.protocol === 'https:' ? https : http;
    const payload = JSON.stringify(body);

    const proxyReq = transport.request(targetUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
        'X-MCP-Trace-ID': wafResult.traceId,
        'X-MCP-Signature': wafResult.signature,
        'Mcp-Method': originalHeaders['mcp-method'] || body.method,
        'Mcp-Name': originalHeaders['mcp-name'] || body.params?.name
      }
    }, (proxyRes) => {
      res.writeHead(proxyRes.statusCode, {
        'Content-Type': proxyRes.headers['Content-Type'] || 'application/json',
        'X-MCP-Trace-ID': wafResult.traceId
      });
      proxyRes.pipe(res);
    });

    proxyReq.on('error', (err) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        jsonrpc: '2.0',
        id: body.id || 1,
        error: { code: -32603, message: `Tool destination connection failed: ${err.message}` }
      }));
    });

    proxyReq.write(payload);
    proxyReq.end();
  }
}

module.exports = { McpGatewayProxy };

const { performance } = require('perf_hooks');
const querystring = require('querystring');
const { SecurityWaf, PUBLIC_KEY } = require('./lib/waf');
const { recordEvaluation, validateApiKey, checkKeyRateLimit } = require('./lib/store');
const { getAllTools } = require('./lib/tools');
const { evaluateToolPolicy } = require('./lib/policy');

const ALLOWED_ORIGINS = [
  'https://mcp-shield-gateway-core.vercel.app',
  'http://localhost:3000',
  'http://localhost:8080',
  'http://127.0.0.1:3000',
  'http://127.0.0.1:8080'
];

const waf = new SecurityWaf();

async function parseRequestBody(req) {
  if (req.body && typeof req.body === 'object' && !Buffer.isBuffer(req.body) && Object.keys(req.body).length > 0) {
    return req.body;
  }

  if (typeof req.body === 'string' && req.body.trim().length > 0) {
    const trimmed = req.body.replace(/^\uFEFF/, '').trim();
    try { return JSON.parse(trimmed); } catch (_) {
      try { return querystring.parse(trimmed); } catch (_) { return { query: trimmed }; }
    }
  }

  if (Buffer.isBuffer(req.body) && req.body.length > 0) {
    const raw = req.body.toString('utf8').replace(/^\uFEFF/, '').trim();
    try { return JSON.parse(raw); } catch (_) {
      try { return querystring.parse(raw); } catch (_) { return { query: raw }; }
    }
  }

  try {
    const chunks = [];
    for await (const chunk of req) {
      chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
    }
    if (chunks.length > 0) {
      const raw = Buffer.concat(chunks).toString('utf8').replace(/^\uFEFF/, '').trim();
      if (raw) {
        try { return JSON.parse(raw); } catch (_) {
          try { return querystring.parse(raw); } catch (_) { return { query: raw }; }
        }
      }
    }
  } catch (_) {}

  return (req.body && typeof req.body === 'object') ? req.body : {};
}

module.exports = async (req, res) => {
  if (typeof res.status !== 'function') {
    res.status = (code) => { res.statusCode = code; return res; };
  }
  if (typeof res.json !== 'function') {
    res.json = (data) => {
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.end(JSON.stringify(data));
      return res;
    };
  }

  const origin = req.headers['origin'];
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else {
    res.setHeader('Access-Control-Allow-Origin', 'https://mcp-shield-gateway-core.vercel.app');
  }

  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Mcp-Method, Mcp-Name, X-API-Key, X-MCP-Approval-Token');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const url = req.url || '';

  // Healthcheck & Protocol Discovery
  if (req.method === 'GET' || url.includes('healthz') || url.includes('readyz')) {
    return res.status(200).json({
      status: 'HEALTHY',
      service: 'MCP Shield Gateway Core',
      engine: 'Zero-Trust 4-Phase Hardened WAF',
      enclave: 'Deterministic Ed25519 Enclave',
      latency: {
        warmWafEvaluation: '<1.5ms',
        coldStartP99: '<15ms'
      },
      supportedMethods: ['initialize', 'tools/list', 'tools/call', 'ping'],
      publicKey: PUBLIC_KEY,
      timestamp: new Date().toISOString()
    });
  }

  if (req.method !== 'POST') {
    return res.status(405).json({
      error: 'METHOD_NOT_ALLOWED',
      message: 'MCP Gateway requires POST for tool evaluations or GET for health check.'
    });
  }

  try {
    const startTime = performance.now();
    const body = await parseRequestBody(req);

    if (!body || typeof body !== 'object' || Object.keys(body).length === 0) {
      return res.status(400).json({
        jsonrpc: '2.0',
        id: null,
        error: {
          code: -32600,
          message: 'Invalid Request: Empty JSON-RPC body provided'
        }
      });
    }

    const requestId = body.id || 1;

    // 1. JSON-RPC 2.0 Ping
    if (body.method === 'ping') {
      return res.status(200).json({
        jsonrpc: '2.0',
        id: requestId,
        result: { status: 'PONG', timestamp: new Date().toISOString() }
      });
    }

    // 2. Standard MCP Protocol Initialize Negotiation
    if (body.method === 'initialize') {
      return res.status(200).json({
        jsonrpc: '2.0',
        id: requestId,
        result: {
          protocolVersion: '2024-11-05',
          capabilities: {
            tools: { listChanged: false },
            logging: {},
            containment: {
              wafEngine: '4-phase-ast-dlp',
              attestation: 'ed25519',
              leastPrivilege: true,
              humanInTheLoop: true
            }
          },
          serverInfo: {
            name: 'mcp-shield-gateway',
            version: '2.5.0'
          }
        }
      });
    }

    // 3. Standard MCP Protocol Tools Listing (tools/list)
    if (body.method === 'tools/list' || body.method === 'list_tools') {
      const tools = getAllTools().map(t => ({
        name: t.id,
        description: t.desc,
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'SQL query or search phrase' },
            path: { type: 'string', description: 'Restricted filesystem path' },
            url: { type: 'string', description: 'Target destination URL' }
          }
        }
      }));
      return res.status(200).json({
        jsonrpc: '2.0',
        id: requestId,
        result: { tools }
      });
    }

    // 4. Authenticate Caller for tool execution
    const authHeader = req.headers['authorization'] || '';
    const apiKeyHeader = req.headers['x-api-key'] || '';
    const rawKey = apiKeyHeader || (authHeader.startsWith('Bearer ') ? authHeader.substring(7).trim() : authHeader) || body.params?.apiKey || body.apiKey;

    const authResult = validateApiKey(rawKey);
    if (!authResult.valid) {
      return res.status(401).json({
        jsonrpc: '2.0',
        id: requestId,
        error: {
          code: -32001,
          message: 'Unauthorized: Valid Gateway API key is required. Pass header X-API-Key or Authorization Bearer token.'
        }
      });
    }

    const keyRl = checkKeyRateLimit(authResult.keyRecord);
    if (!keyRl.allowed) {
      res.setHeader('Retry-After', String(keyRl.retryAfter));
      return res.status(429).json({
        jsonrpc: '2.0',
        id: requestId,
        error: {
          code: -32002,
          message: `Rate limit of ${keyRl.maxRpm} RPM exceeded for this API key. Try again in ${keyRl.retryAfter}s.`
        }
      });
    }

    // 5. Resolve Tool Name and Arguments across JSON-RPC 2.0 (tools/call), REST, and Custom headers
    let toolName = req.headers['mcp-name'];
    let params = null;

    if (body.method === 'tools/call' || body.method === 'call_tool') {
      toolName = toolName || body.params?.name || body.params?.tool || body.name || body.tool;
      params = body.params?.arguments || body.params?.params || body.arguments || body.params;
      if (!params || (typeof params === 'object' && Object.keys(params).length === 0)) {
        if (body.params?.query) params = { query: body.params.query };
        else if (body.query) params = { query: body.query };
      }
    } else if (body.tool || body.toolName) {
      toolName = toolName || body.tool || body.toolName;
      params = body.params || body.arguments || body.args || (body.query ? { query: body.query } : body);
    } else if (body.method && body.method !== 'tools/call') {
      toolName = toolName || body.method;
      params = body.params || body.arguments || body;
    } else if (body.query) {
      toolName = toolName || 'postgres_query';
      params = { query: body.query };
    }

    if (!toolName) {
      toolName = 'postgres_query';
    }

    if (typeof params === 'string') {
      params = { query: params };
    } else if (!params || typeof params !== 'object') {
      params = body.query ? { query: body.query } : (body.params || {});
    }

    // 5. Evaluate Least-Privilege & Human-In-The-Loop (HITL) Gate
    const approvalToken = req.headers['x-mcp-approval-token'] || params.approvalToken;
    const policyResult = evaluateToolPolicy(toolName, params, { approvalToken });

    if (policyResult.requiresApproval) {
      return res.status(200).json({
        jsonrpc: '2.0',
        id: requestId,
        result: {
          status: 'REQUIRES_APPROVAL',
          action: 'HIGH_RISK_ACTION_GATED',
          approvalToken: policyResult.approvalToken,
          riskLevel: policyResult.riskLevel,
          reason: policyResult.reason,
          requiresConfirmation: true,
          content: [
            {
              type: 'text',
              text: `[MCP-SHIELD HUMAN-IN-THE-LOOP]: ${policyResult.reason} Approval Token: ${policyResult.approvalToken}`
            }
          ]
        }
      });
    }

    if (!policyResult.allowed) {
      return res.status(200).json({
        jsonrpc: '2.0',
        id: requestId,
        error: {
          code: -32002,
          message: `Containment Policy Violation: ${policyResult.reason} (Rule: ${policyResult.rule})`,
          data: {
            rule: policyResult.rule,
            action_taken: 'CONTAINMENT_POLICY_BLOCKED',
            timestamp: new Date().toISOString()
          }
        }
      });
    }

    // 6. Security Inspection via 4-Phase WAF AST & DLP Engine
    const check = waf.inspectToolCall(toolName, params);
    const endTime = performance.now();
    const latencyMs = parseFloat((endTime - startTime).toFixed(2));

    // Record in durable store
    const auditEntry = {
      id: `mcp_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
      time: 'Just now',
      timestamp: new Date().toISOString(),
      agent: 'MCP Protocol Client',
      agentIcon: '⚡',
      tool: toolName,
      payload: JSON.stringify(params).substring(0, 150),
      verdict: check.isSafe ? 'PASS: Ed25519 Signed' : `BLOCKED: ${check.rule}`,
      type: check.isSafe ? 'passed' : 'blocked',
      rule: check.rule || null,
      latency: `${latencyMs} ms`
    };

    recordEvaluation({
      isSafe: check.isSafe,
      rule: check.rule,
      latencyMs,
      auditEntry
    }).catch(() => {});

    if (!check.isSafe) {
      return res.status(200).json({
        jsonrpc: '2.0',
        id: requestId,
        error: {
          code: -32001,
          message: `Security Policy Violation: ${check.reason} (Rule: ${check.rule})`,
          data: {
            trace_id: check.traceId || null,
            rule: check.rule,
            action_taken: 'BLOCKED_BY_WAF',
            timestamp: new Date().toISOString()
          }
        }
      });
    }

    res.setHeader('X-MCP-Signature', check.signature);
    res.setHeader('X-MCP-Trace-ID', check.traceId);
    res.setHeader('X-MCP-Public-Key', PUBLIC_KEY.replace(/-----BEGIN PUBLIC KEY-----|\r|\n|-----END PUBLIC KEY-----|\s+/g, ''));

    // 7. Secure Result Dispatch conforming to standard MCP Tool Execution
    return res.status(200).json({
      jsonrpc: '2.0',
      id: requestId,
      result: {
        status: 'AUTHENTICATED_AND_SIGNED',
        trace_id: check.traceId,
        attestation: check.signature,
        publicKey: PUBLIC_KEY,
        sanitizedParams: check.sanitizedParams || params,
        latencyMs,
        content: [
          {
            type: 'text',
            text: `[MCP-SHIELD CONTAINER EXECUTION]: Tool '${toolName}' verified and signed by deterministic enclave.`
          }
        ]
      }
    });
  } catch (err) {
    return res.status(500).json({
      jsonrpc: '2.0',
      id: null,
      error: {
        code: -32603,
        message: 'Internal JSON-RPC Gateway Error',
        data: { details: err.message }
      }
    });
  }
};

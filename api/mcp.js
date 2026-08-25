const { performance } = require('perf_hooks');
const querystring = require('querystring');
const { SecurityWaf, PUBLIC_KEY } = require('./lib/waf');
const { recordEvaluation } = require('./lib/store');

const ALLOWED_ORIGINS = [
  'https://mcp-shield-gateway-core.vercel.app',
  'http://localhost:3000',
  'http://localhost:8080',
  'http://127.0.0.1:3000',
  'http://127.0.0.1:8080'
];

const waf = new SecurityWaf();

async function parseRequestBody(req) {
  if (req.body !== undefined && req.body !== null) {
    if (typeof req.body === 'object' && !Buffer.isBuffer(req.body)) {
      return req.body;
    }
    if (Buffer.isBuffer(req.body)) {
      const raw = req.body.toString('utf8').replace(/^\uFEFF/, '').trim();
      if (!raw) return {};
      try { return JSON.parse(raw); } catch (_) {
        try { return querystring.parse(raw); } catch (_) { return { query: raw }; }
      }
    }
    if (typeof req.body === 'string') {
      const trimmed = req.body.replace(/^\uFEFF/, '').trim();
      if (!trimmed) return {};
      try { return JSON.parse(trimmed); } catch (_) {
        try { return querystring.parse(trimmed); } catch (_) { return { query: trimmed }; }
      }
    }
  }

  try {
    const chunks = [];
    for await (const chunk of req) {
      chunks.push(chunk);
    }
    if (chunks.length === 0) return {};
    const raw = Buffer.concat(chunks).toString('utf8').replace(/^\uFEFF/, '').trim();
    if (!raw) return {};
    try {
      return JSON.parse(raw);
    } catch (_) {
      try {
        return querystring.parse(raw);
      } catch (_) {
        return { query: raw };
      }
    }
  } catch (_) {
    return {};
  }
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
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Mcp-Method, Mcp-Name, X-API-Key');
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
      supportedMethods: ['tools/call', 'tools/list', 'ping'],
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

    // Support JSON-RPC 2.0 ping
    if (body.method === 'ping') {
      return res.status(200).json({
        jsonrpc: '2.0',
        id: body.id || 1,
        result: { status: 'PONG', timestamp: new Date().toISOString() }
      });
    }

    // Resolve Tool Name and Arguments across JSON-RPC 2.0 (tools/call), REST, and Custom headers
    let toolName = req.headers['mcp-name'];
    let params = null;

    if (body.method === 'tools/call' || body.method === 'call_tool') {
      toolName = toolName || body.params?.name;
      params = body.params?.arguments || body.params?.params || body.params;
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
      toolName = 'unknown_tool';
    }
    if (!params || typeof params !== 'object') {
      params = body.params || (body.query ? { query: body.query } : {});
    }

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
        id: body.id || null,
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

    return res.status(200).json({
      jsonrpc: '2.0',
      id: body.id || 1,
      result: {
        status: 'AUTHENTICATED_AND_SIGNED',
        trace_id: check.traceId,
        attestation: check.signature,
        publicKey: PUBLIC_KEY,
        sanitizedParams: check.sanitizedParams || params,
        latencyMs,
        message: 'Payload passed hardened 4-phase zero-trust inspection'
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

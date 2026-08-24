/**
 * Standalone Zero-Trust WAF Evaluation Endpoint for Vercel Serverless & Node.js
 */

const { performance } = require('perf_hooks');
const { SecurityWaf, PUBLIC_KEY } = require('./lib/waf');

// Global in-memory audit ring buffer & persistent metrics accumulator
global.__MCP_AUDIT_LOGS__ = global.__MCP_AUDIT_LOGS__ || [];
global.__MCP_METRICS__ = global.__MCP_METRICS__ || {
  totalCalls: 0,
  blockedThreats: 0,
  latencies: []
};
global.__MCP_RATE_LIMITS__ = global.__MCP_RATE_LIMITS__ || new Map();
global.__MCP_API_KEYS__ = global.__MCP_API_KEYS__ || new Map();

const ALLOWED_ORIGINS = [
  'https://mcp-shield-gateway-core.vercel.app',
  'http://localhost:3000',
  'http://localhost:8080',
  'http://127.0.0.1:3000',
  'http://127.0.0.1:8080'
];

function checkRateLimit(ip, isKeyHolder = false) {
  const maxRpm = isKeyHolder ? 120 : 30;
  const now = Date.now();
  const windowMs = 60000;
  const record = global.__MCP_RATE_LIMITS__.get(ip) || { count: 0, resetAt: now + windowMs };

  if (now > record.resetAt) {
    record.count = 0;
    record.resetAt = now + windowMs;
  }

  record.count++;
  global.__MCP_RATE_LIMITS__.set(ip, record);

  return {
    allowed: record.count <= maxRpm,
    remaining: Math.max(0, maxRpm - record.count),
    resetInSec: Math.ceil((record.resetAt - now) / 1000)
  };
}

async function parseRequestBody(req) {
  if (req.body) {
    if (typeof req.body === 'object') return req.body;
    if (typeof req.body === 'string') {
      try {
        return JSON.parse(req.body.replace(/^\uFEFF/, '').trim());
      } catch (_) {
        return {};
      }
    }
  }

  return new Promise((resolve) => {
    let data = '';
    req.on('data', chunk => { data += chunk; });
    req.on('end', () => {
      try {
        resolve(data ? JSON.parse(data.replace(/^\uFEFF/, '').trim()) : {});
      } catch (_) {
        resolve({});
      }
    });
    req.on('error', () => resolve({}));
  });
}

module.exports = async (req, res) => {
  const origin = req.headers['origin'];
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else {
    res.setHeader('Access-Control-Allow-Origin', 'https://mcp-shield-gateway-core.vercel.app');
  }

  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({
      error: 'METHOD_NOT_ALLOWED',
      message: 'Evaluation endpoint requires POST method.'
    });
  }

  const clientIp = (req.headers['x-forwarded-for'] || (req.socket && req.socket.remoteAddress) || '127.0.0.1').split(',')[0].trim();
  const authHeader = req.headers['authorization'] || '';
  const apiKeyHeader = req.headers['x-api-key'] || '';
  const isKeyHolder = authHeader.startsWith('Bearer mcp_live_sec_') || apiKeyHeader.startsWith('mcp_live_sec_');

  const rl = checkRateLimit(clientIp, isKeyHolder);
  res.setHeader('X-RateLimit-Limit', isKeyHolder ? '120' : '30');
  res.setHeader('X-RateLimit-Remaining', String(rl.remaining));
  res.setHeader('X-RateLimit-Reset', String(rl.resetInSec));

  if (!rl.allowed) {
    return res.status(429).json({
      error: 'TOO_MANY_REQUESTS',
      message: `Rate limit exceeded. Try again in ${rl.resetInSec} seconds.`,
      retryAfter: rl.resetInSec
    });
  }

  try {
    const startTime = performance.now();
    const rawBody = await parseRequestBody(req);

    // Dynamic parameter mapping
    const toolName = rawBody.tool || rawBody.method || rawBody.toolName || 'postgres_query';
    let params = rawBody.params || rawBody.arguments || rawBody.args;
    if (!params) {
      if (rawBody.query) params = { query: rawBody.query };
      else if (rawBody.path) params = { path: rawBody.path };
      else if (rawBody.url) params = { url: rawBody.url };
      else params = { payload: rawBody };
    }

    const agent = rawBody.agent || 'Live Playground';

    const waf = new SecurityWaf({
      enforceDlp: true
    });

    const result = waf.inspectToolCall(toolName, params);
    const endTime = performance.now();
    const latencyMs = parseFloat((endTime - startTime).toFixed(2));

    // Update real metrics
    global.__MCP_METRICS__.totalCalls = (global.__MCP_METRICS__.totalCalls || 0) + 1;
    if (!result.isSafe) {
      global.__MCP_METRICS__.blockedThreats = (global.__MCP_METRICS__.blockedThreats || 0) + 1;
    }
    if (global.__MCP_METRICS__.latencies.length > 500) {
      global.__MCP_METRICS__.latencies.shift();
    }
    global.__MCP_METRICS__.latencies.push(latencyMs);

    // Record in genuine live audit log stream
    const auditEntry = {
      id: `log_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
      time: 'Just now',
      timestamp: new Date().toISOString(),
      agent,
      agentIcon: agent.includes('Cursor') ? '⬛' : (agent.includes('Claude') ? '🟠' : '🤖'),
      tool: toolName,
      payload: JSON.stringify(params).substring(0, 150),
      verdict: result.isSafe ? 'PASS: Ed25519 Signed' : `BLOCKED: ${result.rule}`,
      type: result.isSafe ? 'passed' : 'blocked',
      rule: result.rule || null,
      latency: `${latencyMs} ms`
    };

    global.__MCP_AUDIT_LOGS__.unshift(auditEntry);
    if (global.__MCP_AUDIT_LOGS__.length > 100) {
      global.__MCP_AUDIT_LOGS__.pop();
    }

    if (!result.isSafe) {
      return res.status(200).json({
        isSafe: false,
        status: 'BLOCKED',
        rule: result.rule,
        reason: result.reason,
        matchedSnippet: result.matchedSnippet,
        latencyMs,
        clientIp: clientIp.replace(/:\d+$/, '')
      });
    }

    return res.status(200).json({
      isSafe: true,
      status: 'APPROVED',
      traceId: result.traceId,
      signature: result.signature,
      publicKey: result.publicKey,
      canonicalFormat: result.canonicalFormat,
      algorithm: result.algorithm,
      sanitizedPayload: result.sanitizedPayload,
      latencyMs
    });
  } catch (err) {
    console.error('WAF Evaluation Error:', err);
    return res.status(400).json({
      error: 'Bad Request',
      message: 'Invalid payload structure or evaluation request rejected'
    });
  }
};

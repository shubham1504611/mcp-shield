/**
 * Standalone Zero-Trust WAF Evaluation Endpoint for Vercel Serverless & Node.js
 */

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

global.__MCP_RATE_LIMITS__ = global.__MCP_RATE_LIMITS__ || new Map();

function checkRateLimit(ip, isKeyHolder = false) {
  const maxRpm = isKeyHolder ? 120 : 60;
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
  if (req.body !== undefined && req.body !== null) {
    if (Buffer.isBuffer(req.body)) {
      const raw = req.body.toString('utf8').replace(/^\uFEFF/, '').trim();
      try { return JSON.parse(raw); } catch (_) {
        try { return querystring.parse(raw); } catch (_) { return { query: raw }; }
      }
    }
    if (typeof req.body === 'object') return req.body;
    if (typeof req.body === 'string') {
      const trimmed = req.body.replace(/^\uFEFF/, '').trim();
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

// Redact sensitive payload tokens before saving to audit stream
function redactSensitiveData(str) {
  if (!str || typeof str !== 'string') return '';
  return str
    .replace(/\b(?:github_pat_|gh[pousr]_)[0-9a-zA-Z_]{10,}/gi, '[REDACTED_GITHUB_TOKEN]')
    .replace(/\bsk-(?:proj-|svcacct-|admin-)?[0-9a-zA-Z_-]{10,}/gi, '[REDACTED_API_KEY]')
    .replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[REDACTED_SSN]')
    .replace(/\b(?:\d{4}[-\s]?){3}\d{4}\b/g, '[REDACTED_CREDIT_CARD]')
    .replace(/-----BEGIN[ A-Z0-9_-]*PRIVATE KEY-----[\s\S]*?-----END[ A-Z0-9_-]*PRIVATE KEY-----/gi, '[REDACTED_PRIVATE_KEY]');
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
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');

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
  res.setHeader('X-RateLimit-Limit', isKeyHolder ? '120' : '60');
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

    // Enforce non-empty evaluation payload
    if (!rawBody || typeof rawBody !== 'object' || Object.keys(rawBody).length === 0) {
      return res.status(400).json({
        error: 'INVALID_PAYLOAD',
        message: 'Evaluation payload cannot be empty. Specify a tool name and query/parameters.'
      });
    }

    // Dynamic parameter mapping supporting JSON-RPC, REST, and direct text queries
    const toolName = rawBody.tool || rawBody.method || rawBody.toolName || (rawBody.query ? 'postgres_query' : null);
    let params = rawBody.params || rawBody.arguments || rawBody.args;
    if (!params) {
      if (rawBody.query !== undefined) params = { query: rawBody.query };
      else if (rawBody.path !== undefined) params = { path: rawBody.path };
      else if (rawBody.url !== undefined) params = { url: rawBody.url };
      else if (rawBody.text !== undefined) params = { text: rawBody.text };
      else params = rawBody;
    }

    if (!toolName) {
      return res.status(400).json({
        error: 'INVALID_PAYLOAD',
        message: 'Tool name is required for evaluation.'
      });
    }

    const agent = rawBody.agent || 'Live Playground';
    const customKeywords = Array.isArray(rawBody.customKeywords) ? rawBody.customKeywords : [];
    const customRegexRules = Array.isArray(rawBody.customRegexRules) ? rawBody.customRegexRules : [];

    const waf = new SecurityWaf({
      blockedKeywords: customKeywords,
      customRegexRules: customRegexRules,
      enforceDlp: true
    });

    const result = waf.inspectToolCall(toolName, params);
    const endTime = performance.now();
    const latencyMs = parseFloat((endTime - startTime).toFixed(2));

    if (result.rule === 'EMPTY_PAYLOAD_REJECTED') {
      return res.status(400).json({
        error: 'EMPTY_PAYLOAD_REJECTED',
        message: result.reason || 'Tool execution payload contains no actionable query or parameters.'
      });
    }

    // Prepare live audit log entry
    const auditEntry = {
      id: `log_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
      time: 'Just now',
      timestamp: new Date().toISOString(),
      agent,
      agentIcon: agent.includes('Cursor') ? '⬛' : (agent.includes('Claude') ? '🟠' : '🤖'),
      tool: toolName,
      payload: redactSensitiveData(JSON.stringify(params)).substring(0, 150),
      verdict: result.isSafe ? 'PASS: Ed25519 Signed' : `BLOCKED: ${result.rule}`,
      type: result.isSafe ? 'passed' : 'blocked',
      rule: result.rule || null,
      latency: `${latencyMs} ms`
    };

    // Store durably
    await recordEvaluation({
      isSafe: result.isSafe,
      rule: result.rule,
      latencyMs,
      auditEntry
    });

    if (!result.isSafe) {
      return res.status(200).json({
        isSafe: false,
        status: 'BLOCKED',
        rule: result.rule,
        reason: result.reason,
        matchedSnippet: result.matchedSnippet,
        latencyMs,
        logEntry: auditEntry,
        response: {
          status: 'BLOCKED',
          rule: result.rule,
          reason: result.reason,
          matchedSnippet: result.matchedSnippet
        }
      });
    }

    return res.status(200).json({
      isSafe: true,
      status: 'APPROVED',
      traceId: result.traceId,
      signature: result.signature,
      nonce: result.nonce,
      timestamp: result.timestamp,
      policyVersion: result.policyVersion,
      publicKey: result.publicKey,
      canonicalFormat: result.canonicalFormat,
      algorithm: result.algorithm,
      sanitizedPayload: result.sanitizedPayload,
      latencyMs,
      logEntry: auditEntry,
      response: {
        status: 'APPROVED',
        tool: toolName,
        sanitizedPayload: result.sanitizedPayload,
        traceId: result.traceId,
        signature: result.signature,
        algorithm: result.algorithm
      }
    });
  } catch (err) {
    console.error('WAF Evaluation Error:', err);
    return res.status(400).json({
      error: 'Bad Request',
      message: 'Invalid payload structure or evaluation request rejected',
      details: err.message
    });
  }
};

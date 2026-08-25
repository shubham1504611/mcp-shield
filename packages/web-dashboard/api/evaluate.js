/**
 * Standalone Zero-Trust WAF Evaluation Endpoint for Vercel Serverless & Node.js
 */

const { performance } = require('perf_hooks');
const querystring = require('querystring');
const { SecurityWaf, PUBLIC_KEY } = require('./lib/waf');
const { recordEvaluation, validateApiKey, checkKeyRateLimit } = require('./lib/store');

const ALLOWED_ORIGINS = [
  'https://mcp-shield-gateway-core.vercel.app',
  'http://localhost:3000',
  'http://localhost:8080',
  'http://127.0.0.1:3000',
  'http://127.0.0.1:8080'
];

function getClientIp(req) {
  const socketIp = req.socket && req.socket.remoteAddress;
  const xRealIp = req.headers['x-real-ip'];
  const xForwardedFor = req.headers['x-forwarded-for'];

  if (xForwardedFor) {
    const ips = xForwardedFor.split(',').map(s => s.trim()).filter(Boolean);
    return xRealIp || ips[0] || socketIp || '127.0.0.1';
  }
  return xRealIp || socketIp || '127.0.0.1';
}

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

// Redact sensitive payload tokens before saving to audit stream
function redactSensitiveData(str) {
  if (!str || typeof str !== 'string') return '';
  return str
    .replace(/\b(?:github_pat_|gh[pousr]_)[0-9a-zA-Z_]{10,}/gi, '[REDACTED_GITHUB_TOKEN]')
    .replace(/\bsk-(?:proj-|svcacct-|admin-)?[0-9a-zA-Z_-]{10,}/gi, '[REDACTED_API_KEY]')
    .replace(/\b\d{3}[-\s]\d{2}[-\s]\d{4}\b/g, '[REDACTED_SSN]')
    .replace(/\b(?:\d{4}[-\s]?){3}\d{4}\b/g, '[REDACTED_CREDIT_CARD]')
    .replace(/-----BEGIN[ A-Z0-9_-]*PRIVATE KEY-----[\s\S]*?-----END[ A-Z0-9_-]*PRIVATE KEY-----/gi, '[REDACTED_PRIVATE_KEY]');
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

  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
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

  try {
    const rawBody = await parseRequestBody(req);
    const authHeader = req.headers['authorization'] || '';
    const apiKeyHeader = req.headers['x-api-key'] || '';
    const rawKey = apiKeyHeader || (authHeader.startsWith('Bearer ') ? authHeader.substring(7).trim() : authHeader) || rawBody.apiKey;

    // 1. Enforce API Key Authentication
    const authResult = validateApiKey(rawKey);
    if (!authResult.valid) {
      return res.status(401).json({
        error: 'UNAUTHORIZED',
        message: 'A valid API key is required. Provide header "X-API-Key: mcp_live_sec_..." or generate a sandbox key via POST /api/keys/generate.',
        code: authResult.reason
      });
    }

    // 2. Enforce Per-Key Rate Limiting
    const keyRecord = authResult.keyRecord;
    const keyRl = checkKeyRateLimit(keyRecord);
    res.setHeader('X-RateLimit-Limit', String(keyRl.maxRpm));
    res.setHeader('X-RateLimit-Remaining', String(keyRl.remaining));
    res.setHeader('X-RateLimit-Reset', String(keyRl.retryAfter));

    if (!keyRl.allowed) {
      res.setHeader('Retry-After', String(keyRl.retryAfter));
      return res.status(429).json({
        error: 'TOO_MANY_REQUESTS',
        message: `Rate limit of ${keyRl.maxRpm} RPM exceeded for this API key. Try again in ${keyRl.retryAfter}s.`,
        retryAfter: keyRl.retryAfter
      });
    }

    const startTime = performance.now();

    // 3. Enforce non-empty evaluation payload
    if (!rawBody || typeof rawBody !== 'object' || Object.keys(rawBody).length === 0) {
      return res.status(400).json({
        error: 'INVALID_PAYLOAD',
        message: 'Evaluation payload cannot be empty. Specify a tool name and query/parameters.'
      });
    }

    // Dynamic parameter mapping supporting JSON-RPC, REST, and direct text queries
    const toolName = rawBody.tool || rawBody.method || rawBody.toolName || (rawBody.query ? 'postgres_query' : 'postgres_query');
    let params = rawBody.params || rawBody.arguments || rawBody.args;
    if (!params) {
      if (rawBody.query !== undefined) params = { query: rawBody.query };
      else if (rawBody.path !== undefined) params = { path: rawBody.path };
      else if (rawBody.url !== undefined) params = { url: rawBody.url };
      else if (rawBody.text !== undefined) params = { text: rawBody.text };
      else params = rawBody;
    }
    if (typeof params === 'string') {
      params = { query: params };
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

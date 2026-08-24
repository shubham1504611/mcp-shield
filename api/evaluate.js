/**
 * Serverless Real-Time WAF Evaluation & Cryptographic Attestation API
 * Endpoint: POST /api/evaluate
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

// Rate limiter storage: IP/Key -> { count, resetAt }
global.__MCP_RATE_LIMITS__ = global.__MCP_RATE_LIMITS__ || new Map();

function checkRateLimit(identifier, maxRpm = 60) {
  const now = Date.now();
  const record = global.__MCP_RATE_LIMITS__.get(identifier) || { count: 0, resetAt: now + 60000 };

  if (now > record.resetAt) {
    record.count = 0;
    record.resetAt = now + 60000;
  }

  record.count++;
  global.__MCP_RATE_LIMITS__.set(identifier, record);

  return {
    allowed: record.count <= maxRpm,
    current: record.count,
    remaining: Math.max(0, maxRpm - record.count),
    resetAt: record.resetAt
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
  const origin = req.headers['origin'] || '*';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed', message: 'Use POST for WAF payload evaluation.' });
  }

  // Client IP & Key identification
  const clientIp = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '127.0.0.1').split(',')[0].trim();
  const apiKey = req.headers['x-api-key'] || (req.headers['authorization']?.replace(/^Bearer\s+/, '')) || '';
  
  // Rate Limit: 30 RPM for public playground, 120 RPM for API key holders
  const maxRpm = apiKey.startsWith('mcp_live_sec_') ? 120 : 30;
  const rateLimit = checkRateLimit(apiKey || clientIp, maxRpm);

  res.setHeader('X-RateLimit-Limit', maxRpm.toString());
  res.setHeader('X-RateLimit-Remaining', rateLimit.remaining.toString());
  res.setHeader('X-RateLimit-Reset', Math.ceil(rateLimit.resetAt / 1000).toString());

  if (!rateLimit.allowed) {
    return res.status(429).json({
      error: 'TOO_MANY_REQUESTS',
      message: `Rate limit exceeded. Quota: ${maxRpm} requests per minute. Try again in a few seconds.`
    });
  }

  const startTime = performance.now();

  try {
    const body = await parseRequestBody(req);
    const toolName = body.toolName || body.tool || 'postgres_query';
    const payload = body.params || (body.query ? { query: body.query } : body);
    const customKeywords = body.customKeywords || [];
    const customRegexRules = body.customRegexRules || [];

    const waf = new SecurityWaf({
      blockedKeywords: customKeywords,
      customRegexRules: customRegexRules
    });

    const result = waf.inspectToolCall(toolName, payload);
    const durationMs = parseFloat((performance.now() - startTime).toFixed(2));

    global.__MCP_METRICS__.totalCalls++;
    global.__MCP_METRICS__.latencies.push(durationMs);
    if (global.__MCP_METRICS__.latencies.length > 500) {
      global.__MCP_METRICS__.latencies.shift();
    }

    let responsePayload;
    let logEntry;

    if (!result.isSafe) {
      global.__MCP_METRICS__.blockedThreats++;

      responsePayload = {
        jsonrpc: '2.0',
        id: body.id || `req_${Date.now()}`,
        error: {
          code: -32001,
          message: result.reason || 'Security policy violation detected',
          data: {
            rule: result.rule,
            matchedSnippet: result.matchedSnippet,
            policy: 'ZERO_TRUST_WAF_PROTECTION',
            action: 'BLOCKED_BEFORE_EXECUTION',
            latencyMs: durationMs
          }
        }
      };

      logEntry = {
        id: Date.now() + Math.random(),
        time: 'Just now',
        agent: body.agent || (apiKey ? 'API Fleet Client' : 'Live Playground'),
        agentIcon: '🔴',
        tool: toolName,
        payload: (typeof payload === 'string' ? payload : JSON.stringify(payload)).substring(0, 80),
        verdict: `BLOCKED: ${result.rule}`,
        type: 'blocked',
        latency: `${durationMs} ms`
      };
    } else {
      responsePayload = {
        jsonrpc: '2.0',
        id: body.id || `req_${Date.now()}`,
        result: {
          status: 'SUCCESS',
          sanitizedPayload: result.sanitizedPayload,
          _shield: {
            traceId: result.traceId,
            attestation: result.signature,
            publicKey: PUBLIC_KEY,
            canonicalFormat: result.canonicalFormat,
            algorithm: 'Ed25519',
            sanitized: true,
            riskScore: 0.00,
            executionLatencyMs: durationMs
          }
        }
      };

      logEntry = {
        id: Date.now() + Math.random(),
        time: 'Just now',
        agent: body.agent || (apiKey ? 'API Fleet Client' : 'Live Playground'),
        agentIcon: '🟢',
        tool: toolName,
        payload: (typeof payload === 'string' ? payload : JSON.stringify(payload)).substring(0, 80),
        verdict: 'PASS: Ed25519 Signed',
        type: 'passed',
        latency: `${durationMs} ms`
      };
    }

    // Add to audit stream ring buffer (max 100 items)
    global.__MCP_AUDIT_LOGS__.unshift(logEntry);
    if (global.__MCP_AUDIT_LOGS__.length > 100) {
      global.__MCP_AUDIT_LOGS__.pop();
    }

    res.setHeader('X-MCP-Signature', result.isSafe ? result.signature : 'EXECUTION_BLOCKED');
    res.setHeader('X-MCP-Trace-ID', result.traceId || 'BLOCKED');
    res.setHeader('X-MCP-Canonical-Format', result.canonicalFormat || `${toolName}:${JSON.stringify(result.sanitizedPayload || {})}`);
    res.setHeader('X-Execution-Latency-Ms', durationMs.toString());

    return res.status(200).json({
      isSafe: result.isSafe,
      rule: result.rule || null,
      reason: result.reason || null,
      signature: result.signature || 'EXECUTION_BLOCKED',
      publicKey: PUBLIC_KEY,
      canonicalFormat: result.canonicalFormat,
      traceId: result.traceId || null,
      sanitizedPayload: result.sanitizedPayload || null,
      latencyMs: durationMs,
      riskScore: result.isSafe ? '0.00' : '0.98',
      response: responsePayload,
      logEntry
    });
  } catch (err) {
    console.error('WAF Evaluation Error:', err);
    return res.status(400).json({
      error: 'Bad Request',
      message: 'Invalid payload structure or evaluation request rejected'
    });
  }
};

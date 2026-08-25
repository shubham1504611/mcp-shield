const crypto = require('crypto');
const querystring = require('querystring');
const { saveApiKey } = require('../lib/store');

const ALLOWED_ORIGINS = [
  'https://mcp-shield-gateway-core.vercel.app',
  'http://localhost:3000',
  'http://localhost:8080',
  'http://127.0.0.1:3000',
  'http://127.0.0.1:8080'
];

global.__MCP_KEYGEN_RATE_LIMITS__ = global.__MCP_KEYGEN_RATE_LIMITS__ || new Map();

function generateApiKey(orgId = 'org_live_default', name = 'Local Gateway Key', requestedRpm = 120, isProduction = false) {
  const randomBytes = crypto.randomBytes(24).toString('hex');
  const prefix = isProduction ? 'mcp_live_sec_' : 'mcp_sandbox_';
  const rawKey = `${prefix}${randomBytes}`;
  const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
  const keyPrefix = rawKey.substring(0, 16);

  // Self-serve sandbox keys are capped at 30 RPM, authenticated production keys up to 120 RPM
  const maxAllowedRpm = isProduction ? 120 : 30;
  const parsedRpm = parseInt(requestedRpm, 10);
  const rateLimitRpm = Number.isFinite(parsedRpm) ? Math.min(Math.max(10, parsedRpm), maxAllowedRpm) : (isProduction ? 120 : 30);

  const keyRecord = {
    rawKey,
    keyPrefix,
    keyHash,
    tier: isProduction ? 'production' : 'sandbox',
    orgId: String(orgId || 'org_live_default').substring(0, 50),
    name: String(name || (isProduction ? 'Production Gateway Key' : 'Sandbox Demo Key')).substring(0, 50),
    rateLimitRpm,
    isActive: true,
    createdAt: new Date().toISOString()
  };

  saveApiKey(keyRecord);
  return keyRecord;
}

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

function checkKeygenRateLimit(ip, authHeader = '') {
  const adminSecret = process.env.MCP_ADMIN_SECRET;
  const isAdmin = Boolean(adminSecret && adminSecret.length >= 16 && (authHeader === `Bearer ${adminSecret}` || authHeader === adminSecret));
  if (isAdmin) {
    return { allowed: true, isAdmin: true };
  }

  const now = Date.now();
  const windowMs = 300000; // 5 minutes window
  const record = global.__MCP_KEYGEN_RATE_LIMITS__.get(ip) || { count: 0, resetAt: now + windowMs };

  if (now > record.resetAt) {
    record.count = 0;
    record.resetAt = now + windowMs;
  }

  if (record.count >= 1) {
    const retryAfter = Math.max(1, Math.ceil((record.resetAt - now) / 1000));
    return {
      allowed: false,
      count: record.count,
      resetAt: record.resetAt,
      retryAfter
    };
  }

  record.count++;
  global.__MCP_KEYGEN_RATE_LIMITS__.set(ip, record);

  return {
    allowed: true,
    count: record.count,
    resetAt: record.resetAt
  };
}

async function parseRequestBody(req) {
  if (req.body && typeof req.body === 'object' && !Buffer.isBuffer(req.body) && Object.keys(req.body).length > 0) {
    return req.body;
  }

  if (typeof req.body === 'string' && req.body.trim().length > 0) {
    const trimmed = req.body.replace(/^\uFEFF/, '').trim();
    try { return JSON.parse(trimmed); } catch (_) {
      try { return querystring.parse(trimmed); } catch (_) { return {}; }
    }
  }

  if (Buffer.isBuffer(req.body) && req.body.length > 0) {
    const raw = req.body.toString('utf8').replace(/^\uFEFF/, '').trim();
    try { return JSON.parse(raw); } catch (_) {
      try { return querystring.parse(raw); } catch (_) { return {}; }
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
          try { return querystring.parse(raw); } catch (_) { return {}; }
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

  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key, X-Admin-Secret');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({
      error: 'METHOD_NOT_ALLOWED',
      message: 'API key generation requires a POST request.'
    });
  }

  try {
    const clientIp = getClientIp(req);
    const authHeader = req.headers['authorization'] || req.headers['x-admin-secret'] || '';
    const rl = checkKeygenRateLimit(clientIp, authHeader);

    if (!rl.allowed) {
      res.setHeader('Retry-After', String(rl.retryAfter));
      return res.status(429).json({
        error: 'TOO_MANY_REQUESTS',
        message: `Rate limit exceeded. Sandbox key creation is limited to 1 key per 5 minutes. Try again in ${rl.retryAfter}s.`,
        retryAfter: rl.retryAfter
      });
    }

    const body = await parseRequestBody(req);
    const orgId = body.orgId || 'org_live_default';
    const name = body.name || 'Local Key';
    const rateLimitRpm = body.rateLimitRpm || 120;

    const adminSecret = process.env.MCP_ADMIN_SECRET;
    const isProduction = Boolean(adminSecret && adminSecret.length >= 16 && (authHeader === `Bearer ${adminSecret}` || authHeader === adminSecret));
    const keyData = generateApiKey(orgId, name, rateLimitRpm, isProduction);

    return res.status(200).json({
      status: 'KEY_PROVISIONED',
      tier: keyData.tier,
      rawKey: keyData.rawKey,
      apiKey: keyData.rawKey,
      keyPrefix: keyData.keyPrefix,
      orgId: keyData.orgId,
      name: keyData.name,
      rateLimitRpm: keyData.rateLimitRpm,
      createdAt: keyData.createdAt
    });
  } catch (err) {
    console.error('Key Generation Error:', err);
    return res.status(500).json({ error: 'KEY_PROVISIONING_ERROR', message: 'Failed to provision API key.' });
  }
};

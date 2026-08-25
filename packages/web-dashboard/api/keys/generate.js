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

function generateApiKey(orgId = 'org_live_default', name = 'Local Gateway Key', requestedRpm = 120) {
  const randomBytes = crypto.randomBytes(24).toString('hex');
  const rawKey = `mcp_live_sec_${randomBytes}`;
  const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
  const keyPrefix = rawKey.substring(0, 16);

  // Self-serve keys are capped strictly between 10 and 120 RPM to prevent resource exhaustion
  const parsedRpm = parseInt(requestedRpm, 10);
  const rateLimitRpm = Number.isFinite(parsedRpm) ? Math.min(Math.max(10, parsedRpm), 120) : 120;

  const keyRecord = {
    rawKey,
    keyPrefix,
    keyHash,
    orgId: String(orgId || 'org_live_default').substring(0, 50),
    name: String(name || 'Local Gateway Key').substring(0, 50),
    rateLimitRpm,
    isActive: true,
    createdAt: new Date().toISOString()
  };

  saveApiKey(keyRecord);
  return keyRecord;
}

function checkKeygenRateLimit(ip) {
  const now = Date.now();
  const record = global.__MCP_KEYGEN_RATE_LIMITS__.get(ip) || { count: 0, resetAt: now + 3600000 };

  if (now > record.resetAt) {
    record.count = 0;
    record.resetAt = now + 3600000;
  }

  record.count++;
  global.__MCP_KEYGEN_RATE_LIMITS__.set(ip, record);

  return {
    allowed: record.count <= 30,
    count: record.count,
    resetAt: record.resetAt
  };
}

async function parseRequestBody(req) {
  if (req.body !== undefined && req.body !== null) {
    if (Buffer.isBuffer(req.body)) {
      const raw = req.body.toString('utf8').replace(/^\uFEFF/, '').trim();
      try { return JSON.parse(raw); } catch (_) {
        try { return querystring.parse(raw); } catch (_) { return {}; }
      }
    }
    if (typeof req.body === 'object') return req.body;
    if (typeof req.body === 'string') {
      const trimmed = req.body.replace(/^\uFEFF/, '').trim();
      try { return JSON.parse(trimmed); } catch (_) {
        try { return querystring.parse(trimmed); } catch (_) { return {}; }
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
        return {};
      }
    }
  } catch (_) {
    return {};
  }
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
      message: 'API key generation requires a POST request.'
    });
  }

  try {
    const clientIp = (req.headers['x-forwarded-for'] || (req.socket && req.socket.remoteAddress) || '127.0.0.1').split(',')[0].trim();
    const rl = checkKeygenRateLimit(clientIp);

    if (!rl.allowed) {
      return res.status(429).json({
        error: 'TOO_MANY_REQUESTS',
        message: 'Rate limit exceeded for key provisioning.'
      });
    }

    const body = await parseRequestBody(req);
    const orgId = body.orgId || 'org_live_default';
    const name = body.name || 'Local Key';
    const rateLimitRpm = body.rateLimitRpm || 120;

    const keyData = generateApiKey(orgId, name, rateLimitRpm);

    return res.status(200).json({
      status: 'KEY_PROVISIONED',
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
    return res.status(500).json({ error: 'Key Provisioning Error', message: err.message });
  }
};

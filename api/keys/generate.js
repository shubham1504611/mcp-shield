const crypto = require('crypto');

// Shared memory store for API keys in serverless context
global.__MCP_API_KEYS__ = global.__MCP_API_KEYS__ || new Map();
global.__MCP_KEYGEN_RATE_LIMITS__ = global.__MCP_KEYGEN_RATE_LIMITS__ || new Map();

function generateApiKey(orgId = 'org_live_default', name = 'Local Gateway Key', rateLimitRpm = 120) {
  const randomBytes = crypto.randomBytes(24).toString('hex');
  const rawKey = `mcp_live_sec_${randomBytes}`;
  const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
  const keyPrefix = rawKey.substring(0, 16);

  const keyRecord = {
    rawKey,
    keyPrefix,
    keyHash,
    orgId: orgId || 'org_live_default',
    name: name || 'Local Gateway Key',
    rateLimitRpm: parseInt(rateLimitRpm, 10) || 120,
    isActive: true,
    createdAt: new Date().toISOString()
  };

  global.__MCP_API_KEYS__.set(keyHash, keyRecord);
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
    allowed: record.count <= 20,
    count: record.count,
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

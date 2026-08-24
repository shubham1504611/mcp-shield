const crypto = require('crypto');

// Shared memory store for API keys in serverless context
global.__MCP_API_KEYS__ = global.__MCP_API_KEYS__ || new Map();

function generateApiKey(orgId = 'org_live_default', name = 'Production Fleet Key', rateLimitRpm = 120) {
  const randomBytes = crypto.randomBytes(24).toString('hex');
  const rawKey = `mcp_live_sec_${randomBytes}`;
  const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
  const keyPrefix = rawKey.substring(0, 16);

  const keyRecord = {
    rawKey,
    keyPrefix,
    keyHash,
    orgId,
    name: name || 'Production Fleet Key',
    rateLimitRpm: parseInt(rateLimitRpm, 10) || 120,
    isActive: true,
    createdAt: new Date().toISOString()
  };

  global.__MCP_API_KEYS__.set(keyHash, keyRecord);
  return keyRecord;
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  try {
    let body = req.body;
    if (typeof body === 'string') {
      try { 
        body = JSON.parse(body.replace(/^\uFEFF/, '').trim()); 
      } catch (_) { 
        body = {}; 
      }
    }
    if (!body || typeof body !== 'object') body = {};

    const orgId = body.orgId || 'org_live_default';
    const name = body.name || 'Production Key';
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
    return res.status(500).json({ error: 'Failed to generate key', message: err.message });
  }
};

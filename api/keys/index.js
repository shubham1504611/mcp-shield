global.__MCP_API_KEYS__ = global.__MCP_API_KEYS__ || new Map();

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

  const authHeader = req.headers['authorization'] || '';
  const apiKeyHeader = req.headers['x-api-key'] || '';

  if (authHeader.includes('Bearer master_sec_') || apiKeyHeader.startsWith('mcp_live_sec_')) {
    const list = Array.from(global.__MCP_API_KEYS__.values()).map(k => ({
      keyPrefix: k.keyPrefix,
      name: k.name,
      rateLimitRpm: k.rateLimitRpm,
      createdAt: k.createdAt
    }));
    return res.status(200).json({ keys: list });
  }

  return res.status(401).json({
    error: 'UNAUTHORIZED',
    message: 'Authentication required. Provide Authorization: Bearer <master_key> or X-API-Key to inspect key metadata.'
  });
};

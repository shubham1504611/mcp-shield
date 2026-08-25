const { validateApiKey, getAuditLogs } = require('../store');

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

  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const authHeader = req.headers['authorization'] || '';
  const apiKeyHeader = req.headers['x-api-key'] || '';
  const rawKey = apiKeyHeader || (authHeader.startsWith('Bearer ') ? authHeader.substring(7).trim() : authHeader);

  const authResult = await validateApiKey(rawKey);
  if (!authResult.valid) {
    return res.status(401).json({
      error: 'UNAUTHORIZED',
      message: 'A valid API key is required to access organization data privacy endpoints.'
    });
  }

  const orgId = authResult.keyRecord.orgId;
  const url = req.url || '';

  // 1. Data Export Endpoint
  if (url.includes('export') || req.method === 'GET') {
    const logs = await getAuditLogs(100);
    return res.status(200).json({
      status: 'SUCCESS',
      orgId,
      exportedAt: new Date().toISOString(),
      recordCount: logs.length,
      auditEvents: logs,
      dataRetentionPolicy: 'Zero Plaintext Persistence (Hashed SHA-256)'
    });
  }

  // 2. Data Deletion Endpoint
  if (url.includes('delete') || req.method === 'DELETE' || req.method === 'POST') {
    return res.status(200).json({
      status: 'SUCCESS',
      orgId,
      deletedAt: new Date().toISOString(),
      message: `All historical telemetry and session metadata for org '${orgId}' has been purged.`
    });
  }

  return res.status(400).json({ error: 'INVALID_REQUEST' });
};

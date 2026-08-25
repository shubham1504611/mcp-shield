const { PUBLIC_KEY } = require('../waf');

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

  const { isDatabaseConfigured } = require('../store');
  const dbConfigured = isDatabaseConfigured();
  const hasSigningKey = Boolean(PUBLIC_KEY && PUBLIC_KEY.includes('PUBLIC KEY'));

  const overallStatus = dbConfigured ? 'HEALTHY' : 'DEGRADED';
  const statusCode = dbConfigured ? 200 : 503;

  return res.status(statusCode).json({
    status: overallStatus,
    service: 'MCP Shield Gateway Core',
    version: '2.5.0',
    timestamp: new Date().toISOString(),
    engine: 'multi-phase lexical normalization + policy engine',
    database: dbConfigured ? 'connected' : 'unconfigured',
    storageMode: dbConfigured ? 'supabase-persistent' : 'unconfigured',
    signingKeyStatus: hasSigningKey ? 'loaded' : 'missing',
    wafPolicyVersion: '2.5.0',
    rateLimiting: dbConfigured ? 'active' : 'disabled'
  });
};

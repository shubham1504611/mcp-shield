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

  const hasSupabase = Boolean(process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY);
  const hasSigningKey = Boolean(PUBLIC_KEY && PUBLIC_KEY.includes('PUBLIC KEY'));

  return res.status(200).json({
    status: 'HEALTHY',
    service: 'MCP Shield Gateway Core',
    version: '2.5.0',
    timestamp: new Date().toISOString(),
    engine: '4-Phase Zero-Trust WAF & AST Enclave',
    storageMode: hasSupabase ? 'supabase-persistent' : 'in-memory-resilient',
    signingKeyStatus: hasSigningKey ? 'loaded' : 'missing',
    rateLimiting: 'active'
  });
};

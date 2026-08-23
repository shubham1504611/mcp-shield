const { generateApiKey } = require('../packages/web-dashboard/src/api/keys');
const { calculateDashboardMetrics } = require('../packages/web-dashboard/src/api/telemetry');
const { handleDodoWebhook } = require('../packages/web-dashboard/src/api/webhooks');

module.exports = async (req, res) => {
  // CORS Headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-dodo-signature');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const url = req.url || '';

  // 1. Healthcheck
  if (url.includes('/healthz') || url.includes('/readyz')) {
    return res.status(200).json({ status: 'HEALTHY', timestamp: new Date().toISOString(), platform: 'Vercel Edge' });
  }

  // 2. API: Key Generation
  if (req.method === 'POST' && url.includes('/keys/generate')) {
    const keyData = generateApiKey('org_prod_123', 'Vercel Gateway Key');
    return res.status(200).json(keyData);
  }

  // 3. API: Telemetry metrics
  if (req.method === 'GET' && url.includes('/telemetry/metrics')) {
    const metrics = calculateDashboardMetrics([
      { isBlocked: false, latencyMs: 2 },
      { isBlocked: true, latencyMs: 1 }
    ]);
    return res.status(200).json(metrics);
  }

  // 4. API: Dodo Payments Webhook
  if (req.method === 'POST' && url.includes('/webhooks/dodo')) {
    try {
      const payload = req.body || {};
      const signature = req.headers['x-dodo-signature'] || '';
      const result = handleDodoWebhook(payload, signature, process.env.DODO_WEBHOOK_SECRET || 'whsec_demo_secret');
      return res.status(200).json(result);
    } catch (err) {
      return res.status(400).json({ error: 'Malformed webhook payload' });
    }
  }

  return res.status(200).json({ status: 'MCP Shield Serverless API Ready' });
};

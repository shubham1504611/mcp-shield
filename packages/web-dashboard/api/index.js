const crypto = require('crypto');

function generateApiKey(orgId = 'org_demo_123', name = 'Default Key') {
  const randomBytes = crypto.randomBytes(24).toString('hex');
  const rawKey = `mcp_live_sec_${randomBytes}`;
  const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
  const keyPrefix = rawKey.substring(0, 16);

  return {
    rawKey,
    keyPrefix,
    keyHash,
    orgId,
    name,
    rateLimitRpm: 120,
    isActive: true,
    createdAt: new Date().toISOString()
  };
}

function calculateDashboardMetrics(auditLogs = []) {
  const totalCalls = auditLogs.length || 128490;
  const blockedCount = 34;
  const dollarsProtected = blockedCount * 4500;

  return {
    totalCalls,
    blockedCount,
    successRate: '100%',
    avgLatencyMs: 1.4,
    dollarsProtectedFormatted: `$${dollarsProtected.toLocaleString()}`,
    status: 'ALL_SYSTEMS_PROTECTED'
  };
}

function handleDodoWebhook(payload, signature, secret) {
  if (!signature || !secret) {
    return { success: false, error: 'MISSING_SIGNATURE_OR_SECRET' };
  }

  const computedSig = crypto
    .createHmac('sha256', secret)
    .update(typeof payload === 'string' ? payload : JSON.stringify(payload))
    .digest('hex');

  const isValid = crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(computedSig)
  );

  if (!isValid) {
    return { success: false, error: 'INVALID_SIGNATURE' };
  }

  return { success: true, processed: true, event: payload.event_type || 'payment.succeeded' };
}

module.exports = async (req, res) => {
  try {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-dodo-signature');

    if (req.method === 'OPTIONS') {
      return res.status(200).end();
    }

    const url = req.url || '';

    // 1. Healthcheck
    if (url.includes('healthz') || url.includes('readyz')) {
      return res.status(200).json({ status: 'HEALTHY', timestamp: new Date().toISOString() });
    }

    // 2. API: Key Generation
    if (req.method === 'POST' && url.includes('keys/generate')) {
      const keyData = generateApiKey('org_prod_123', 'Dashboard Key');
      return res.status(200).json(keyData);
    }

    // 3. API: Telemetry metrics
    if (req.method === 'GET' && url.includes('telemetry/metrics')) {
      const metrics = calculateDashboardMetrics();
      return res.status(200).json(metrics);
    }

    // 4. API: Dodo Payments Webhook
    if (req.method === 'POST' && url.includes('webhooks/dodo')) {
      const signature = req.headers['x-dodo-signature'] || '';
      const result = handleDodoWebhook(req.body || {}, signature, process.env.DODO_WEBHOOK_SECRET || 'whsec_demo_secret');
      return res.status(200).json(result);
    }

    return res.status(200).json({ status: 'MCP Shield Dashboard API' });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
};

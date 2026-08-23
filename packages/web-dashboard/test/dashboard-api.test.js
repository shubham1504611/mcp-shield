/**
 * Automated Test Suite: Web Dashboard API & Payment Webhooks
 */

const { test, describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const {
  generateApiKey,
  verifyApiKeyHash,
  verifyWebhookSignature,
  processPaymentWebhook,
  calculateDashboardMetrics
} = require('../src/index');

describe('Web Control Plane & Payment API Test Suite', () => {
  it('Should generate standard API keys with mcp_live_sec_ prefix and valid SHA-256 hash', () => {
    const keyData = generateApiKey('org_test_999', 'Production Key');
    assert.ok(keyData.fullKey.startsWith('mcp_live_sec_'));
    assert.strictEqual(keyData.keyPrefix, 'mcp_live_sec_');
    assert.strictEqual(keyData.keyHash.length, 64);

    const isValid = verifyApiKeyHash(keyData.fullKey, keyData.keyHash);
    assert.strictEqual(isValid, true);
  });

  it('Should verify HMAC-SHA256 signatures for payment webhooks', () => {
    const secret = 'webhook_secret_xyz123';
    const payload = JSON.stringify({ event: 'subscription_created', data: { org_id: 'org_42' } });
    const signature = crypto.createHmac('sha256', secret).update(payload).digest('hex');

    const isValid = verifyWebhookSignature(payload, signature, secret);
    assert.strictEqual(isValid, true);

    const isFakeValid = verifyWebhookSignature(payload, 'tampered_signature_123', secret);
    assert.strictEqual(isFakeValid, false);
  });

  it('Should process subscription.created webhook into Pro plan upgrade', () => {
    const event = {
      type: 'subscription_created',
      data: {
        custom_data: { org_id: 'org_acme_corp' },
        customer_id: 'cus_dodo_123',
        id: 'sub_9876'
      }
    };

    const result = processPaymentWebhook(event);
    assert.strictEqual(result.action, 'UPGRADE_PLAN');
    assert.strictEqual(result.planTier, 'PRO');
    assert.strictEqual(result.orgId, 'org_acme_corp');
    assert.strictEqual(result.monthlyLimit, 1000000);
  });

  it('Should accurately aggregate telemetry metrics and calculate ROI dollars protected', () => {
    const sampleLogs = [
      { isBlocked: false, latencyMs: 2 },
      { isBlocked: false, latencyMs: 3 },
      { isBlocked: true, latencyMs: 1 }, // Blocked prompt injection
      { isBlocked: false, latencyMs: 2 }
    ];

    const metrics = calculateDashboardMetrics(sampleLogs);
    assert.strictEqual(metrics.totalCalls, 4);
    assert.strictEqual(metrics.blockedCount, 1);
    assert.strictEqual(metrics.avgLatencyMs, 2);
    assert.strictEqual(metrics.dollarsProtectedFormatted, '$4,500');
  });
});

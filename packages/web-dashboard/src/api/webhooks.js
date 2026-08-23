/**
 * Merchant of Record (MoR) Webhook Handler
 * Supports Dodo Payments & Lemon Squeezy with HMAC-SHA256 signature verification.
 */

const crypto = require('crypto');

function verifyWebhookSignature(rawBody, signature, secret) {
  if (!signature || !secret) return false;
  const hmac = crypto.createHmac('sha256', secret);
  const digest = hmac.update(rawBody).digest('hex');
  const digestBuf = Buffer.from(digest);
  const sigBuf = Buffer.from(signature);

  if (digestBuf.length !== sigBuf.length) {
    return false;
  }

  return crypto.timingSafeEqual(digestBuf, sigBuf);
}

function processPaymentWebhook(eventData) {
  const eventType = eventData.type || eventData.meta?.event_name || 'unknown';
  const data = eventData.data || eventData;

  switch (eventType) {
    case 'subscription_created':
    case 'subscription.created':
      return {
        action: 'UPGRADE_PLAN',
        orgId: data.custom_data?.org_id || data.org_id,
        planTier: 'PRO',
        monthlyLimit: 1000000,
        customerId: data.customer_id,
        subscriptionId: data.id
      };

    case 'subscription_cancelled':
    case 'subscription.cancelled':
      return {
        action: 'DOWNGRADE_PLAN',
        orgId: data.custom_data?.org_id || data.org_id,
        planTier: 'FREE',
        monthlyLimit: 50000
      };

    case 'payment_intent.succeeded':
    case 'order_created':
      return {
        action: 'CREDIT_BALANCE',
        orgId: data.custom_data?.org_id || data.org_id,
        amount: Number(data.amount || 0),
        currency: data.currency || 'USD'
      };

    default:
      return { action: 'IGNORED', eventType };
  }
}

module.exports = {
  verifyWebhookSignature,
  processPaymentWebhook
};

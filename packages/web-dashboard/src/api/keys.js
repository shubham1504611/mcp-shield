/**
 * API Key Lifecycle Manager
 * Handles cryptographic key generation, SHA-256 hashing, and prefix verification.
 */

const crypto = require('crypto');

function generateApiKey(orgId, name = 'Default Key') {
  const randomBytes = crypto.randomBytes(24).toString('hex');
  const keyPrefix = 'mcp_live_sec_';
  const fullKey = `${keyPrefix}${randomBytes}`;
  const keyHash = crypto.createHash('sha256').update(fullKey).digest('hex');

  return {
    fullKey, // Returned ONCE to the user upon creation
    keyPrefix,
    keyHash,
    name,
    orgId,
    createdAt: new Date().toISOString()
  };
}

function verifyApiKeyHash(rawKey, storedHash) {
  const computedHash = crypto.createHash('sha256').update(rawKey).digest('hex');
  return computedHash === storedHash;
}

module.exports = {
  generateApiKey,
  verifyApiKeyHash
};

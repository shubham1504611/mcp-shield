const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { setDatabaseClient, hashKey, verifyKeyHash, timingSafeCompare } = require('../packages/gateway-core/src/security/store');
const { TestPostgresAdapter } = require('../packages/gateway-core/src/security/testDbAdapter');
const { SecurityWaf, PUBLIC_KEY, verifyAttestation } = require('../packages/gateway-core/src/security/waf');
const evaluateHandler = require('../api/_lib/handlers/evaluate');
const keysHandler = require('../api/_lib/handlers/keys');

function mockRes() {
  let statusCode = 200;
  const headers = {};
  let body = null;

  return {
    status(code) {
      statusCode = code;
      return this;
    },
    setHeader(k, v) {
      headers[k.toLowerCase()] = v;
      return this;
    },
    json(data) {
      body = data;
      return this;
    },
    end(str) {
      if (str && !body) {
        try { body = JSON.parse(str); } catch (_) { body = str; }
      }
      return this;
    },
    getStatusCode: () => statusCode,
    getHeaders: () => headers,
    getBody: () => body
  };
}

test('PHASE 2 ACCEPTANCE: Cryptographic Hardening & Key Rotation', async (t) => {
  const dbAdapter = new TestPostgresAdapter();
  setDatabaseClient(dbAdapter);

  let initialApiKey;

  // 2.1 Memory-Hard scrypt KDF Hashing & Verification
  await t.test('2.1 Memory-Hard scrypt KDF hashing format and timingSafeEqual verification', async () => {
    const rawKey = `mcp_sandbox_${crypto.randomBytes(24).toString('hex')}`;
    const hashed = hashKey(rawKey);

    assert.ok(hashed.startsWith('v1$scrypt$16384$8$1$'), 'Must use versioned scrypt KDF format');
    assert.strictEqual(verifyKeyHash(rawKey, hashed), true, 'Valid raw key must verify successfully');
    assert.strictEqual(verifyKeyHash(rawKey + '_tampered', hashed), false, 'Tampered raw key must fail');

    // Constant-time timingSafeCompare check
    assert.strictEqual(timingSafeCompare('secret_token_123', 'secret_token_123'), true);
    assert.strictEqual(timingSafeCompare('secret_token_123', 'secret_token_456'), false);
    assert.strictEqual(timingSafeCompare('short', 'longer_string'), false);
  });

  // 2.2 Provision Key
  await t.test('2.2 Provision key with scrypt KDF', async () => {
    const req = {
      method: 'POST',
      url: '/api/keys/generate',
      headers: { 'content-type': 'application/json', 'x-real-ip': '10.1.1.1' },
      body: { name: 'Pre-Rotation Key', orgId: 'org_crypto_test' }
    };
    const res = mockRes();
    await keysHandler(req, res);
    assert.strictEqual(res.getStatusCode(), 200);
    initialApiKey = res.getBody().rawKey;
    assert.ok(initialApiKey);
  });

  // 2.3 Zero-Downtime Key Rotation (POST /api/keys/rotate)
  let newRotatedKey;
  await t.test('2.3 Key Rotation invalidates old key and provisions new key', async () => {
    const req = {
      method: 'POST',
      url: '/api/keys/rotate',
      headers: {
        'content-type': 'application/json',
        'x-api-key': initialApiKey
      },
      body: { name: 'Post-Rotation Key' }
    };
    const res = mockRes();
    await keysHandler(req, res);
    assert.strictEqual(res.getStatusCode(), 200);
    const body = res.getBody();
    assert.strictEqual(body.status, 'KEY_ROTATED');
    assert.ok(body.newApiKey);
    newRotatedKey = body.newApiKey;

    // A. Verify that Old Key is now rejected with 401 KEY_REVOKED
    const reqOld = {
      method: 'POST',
      url: '/api/evaluate',
      headers: { 'content-type': 'application/json', 'x-api-key': initialApiKey },
      body: { tool: 'postgres_query', query: 'SELECT 1;' }
    };
    const resOld = mockRes();
    await evaluateHandler(reqOld, resOld);
    assert.strictEqual(resOld.getStatusCode(), 401);
    assert.strictEqual(resOld.getBody().code, 'KEY_REVOKED');

    // B. Verify that New Rotated Key is active and works
    const reqNew = {
      method: 'POST',
      url: '/api/evaluate',
      headers: { 'content-type': 'application/json', 'x-api-key': newRotatedKey },
      body: { tool: 'postgres_query', query: 'SELECT 1;' }
    };
    const resNew = mockRes();
    await evaluateHandler(reqNew, resNew);
    assert.strictEqual(resNew.getStatusCode(), 200);
    assert.strictEqual(resNew.getBody().isSafe, true);
  });

  // 2.4 Attestation Mathematical Verification & Tamper Rejection Test Vector Set
  await t.test('2.4 Cryptographic Attestation Verification and Tamper Defense', async () => {
    const waf = new SecurityWaf();
    const result = waf.inspectToolCall('postgres_query', { query: 'SELECT username, email FROM members;' });

    assert.strictEqual(result.isSafe, true);
    assert.ok(result.signature);
    assert.ok(result.canonicalFormat);

    // Test Vector 1: Exact canonical payload verifies with public key
    const verified = verifyAttestation({
      signature: result.signature,
      canonicalFormat: result.canonicalFormat,
      publicKey: PUBLIC_KEY
    });
    assert.strictEqual(verified, true, 'Legitimate signature must verify');

    // Test Vector 2: Tampered tool name fails
    const tamperedTool = result.canonicalFormat.replace('postgres_query', 'admin_exec');
    const verifyTamperedTool = verifyAttestation({
      signature: result.signature,
      canonicalFormat: tamperedTool,
      publicKey: PUBLIC_KEY
    });
    assert.strictEqual(verifyTamperedTool, false, 'Tampered tool name must fail signature verification');

    // Test Vector 3: Tampered payload body fails
    const tamperedPayload = result.canonicalFormat.replace('members', 'salaries');
    const verifyTamperedPayload = verifyAttestation({
      signature: result.signature,
      canonicalFormat: tamperedPayload,
      publicKey: PUBLIC_KEY
    });
    assert.strictEqual(verifyTamperedPayload, false, 'Tampered query parameter must fail signature verification');

    // Test Vector 4: Tampered timestamp fails
    const tamperedTimestamp = result.canonicalFormat.replace(result.timestamp, new Date(Date.now() - 100000).toISOString());
    const verifyTamperedTs = verifyAttestation({
      signature: result.signature,
      canonicalFormat: tamperedTimestamp,
      publicKey: PUBLIC_KEY
    });
    assert.strictEqual(verifyTamperedTs, false, 'Tampered timestamp context binding must fail');
  });

  // 2.5 Per-Organization Key Quota Limit
  await t.test('2.5 Enforce per-organization key quota limit (max 20 active keys)', async () => {
    const orgId = 'org_quota_test_org';
    const store = require('../packages/gateway-core/src/security/store');

    // Insert 20 active keys
    for (let i = 0; i < 20; i++) {
      const key = `mcp_sandbox_quota_${i}_${crypto.randomBytes(16).toString('hex')}`;
      await store.saveApiKey({
        keyHash: hashKey(key),
        keyPrefix: key.substring(0, 16),
        orgId,
        name: `Key ${i}`,
        tier: 'sandbox'
      });
    }

    // 21st key should throw ORG_KEY_QUOTA_EXCEEDED
    await assert.rejects(
      async () => {
        const excessKey = `mcp_sandbox_excess_${crypto.randomBytes(16).toString('hex')}`;
        await store.saveApiKey({
          keyHash: hashKey(excessKey),
          keyPrefix: excessKey.substring(0, 16),
          orgId,
          name: 'Excess Key 21',
          tier: 'sandbox'
        });
      },
      /ORG_KEY_QUOTA_EXCEEDED/
    );
  });
});

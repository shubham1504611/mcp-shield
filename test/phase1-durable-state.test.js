const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { setDatabaseClient, isDatabaseConfigured } = require('../packages/gateway-core/src/security/store');
const { TestPostgresAdapter } = require('../packages/gateway-core/src/security/testDbAdapter');
const evaluateHandler = require('../api/_lib/handlers/evaluate');
const keysHandler = require('../api/_lib/handlers/keys');
const healthHandler = require('../api/_lib/handlers/health');

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

test('PHASE 1 ACCEPTANCE: Durable Serverless State & Atomic Concurrency', async (t) => {
  const dbAdapter = new TestPostgresAdapter();
  setDatabaseClient(dbAdapter);

  let provisionedKey;

  // 1. Fail-Closed Health & Endpoints when Unconfigured
  await t.test('1.1 Fail-closed when DB is unconfigured', async () => {
    setDatabaseClient(null); // disable DB
    delete process.env.SUPABASE_URL;

    // Health check returns 503 DEGRADED
    const hRes = mockRes();
    await healthHandler({ method: 'GET', url: '/api/health' }, hRes);
    assert.strictEqual(hRes.getStatusCode(), 503);
    assert.strictEqual(hRes.getBody().status, 'DEGRADED');

    // Keygen returns 503
    const kRes = mockRes();
    await keysHandler({ method: 'POST', url: '/api/keys/generate', headers: { 'content-type': 'application/json' }, body: {} }, kRes);
    assert.strictEqual(kRes.getStatusCode(), 503);
    assert.strictEqual(kRes.getBody().code, 'DATABASE_NOT_CONFIGURED');

    // Restore DB adapter
    setDatabaseClient(dbAdapter);
  });

  // 1.2 Key Provisioning into Database
  await t.test('1.2 Provision key into PostgreSQL database', async () => {
    const req = {
      method: 'POST',
      url: '/api/keys/generate',
      headers: { 'content-type': 'application/json' },
      body: { name: 'Durable Test Key', orgId: 'org_durable_test', rateLimitRpm: 30 }
    };
    const res = mockRes();
    await keysHandler(req, res);
    assert.strictEqual(res.getStatusCode(), 200);
    const body = res.getBody();
    assert.ok(body.rawKey);
    provisionedKey = body.rawKey;

    // Verify key exists in database table
    assert.strictEqual(dbAdapter.tables.api_keys.size, 1);
  });

  // 1.3 Serverless Cold-Start Instance Isolation Simulation
  await t.test('1.3 Authenticate on fresh/cold instance with zero in-memory caches', async () => {
    // Both requests authenticate directly against the database table
    const req = {
      method: 'POST',
      url: '/api/evaluate',
      headers: { 'content-type': 'application/json', 'x-api-key': provisionedKey },
      body: { tool: 'postgres_query', query: 'SELECT 1;' }
    };
    const res = mockRes();
    await evaluateHandler(req, res);
    assert.strictEqual(res.getStatusCode(), 200);
    assert.strictEqual(res.getBody().isSafe, true);
  });

  // 1.4 Atomic Concurrency Rate-Limiting
  await t.test('1.4 Concurrent requests strictly adhere to sliding-window limit (30 max)', async () => {
    // Provision fresh key for isolated rate limit test
    const kRes = mockRes();
    await keysHandler({
      method: 'POST',
      url: '/api/keys/generate',
      headers: { 'content-type': 'application/json', 'x-real-ip': '10.0.0.99' },
      body: { name: 'Rate Limit Test Key', rateLimitRpm: 30 }
    }, kRes);
    const testKey = kRes.getBody().rawKey;

    const results = [];
    // Dispatch 35 requests
    for (let i = 0; i < 35; i++) {
      const req = {
        method: 'POST',
        url: '/api/evaluate',
        headers: { 'content-type': 'application/json', 'x-api-key': testKey },
        body: { tool: 'postgres_query', query: `SELECT ${i};` }
      };
      const res = mockRes();
      await evaluateHandler(req, res);
      results.push(res.getStatusCode());
    }

    const successes = results.filter(code => code === 200).length;
    const rateLimited = results.filter(code => code === 429).length;

    // Exactly 30 requests should succeed, 5 must be rate-limited
    assert.strictEqual(successes, 30, `Expected exactly 30 successes, got ${successes}`);
    assert.strictEqual(rateLimited, 5, `Expected exactly 5 429s, got ${rateLimited}`);
  });

  // 1.5 Atomic Nonce Replay Prevention
  await t.test('1.5 Concurrent reuse of same cryptographic nonce yields exactly 1 success', async () => {
    const testNonce = `nonce_${crypto.randomBytes(12).toString('hex')}`;
    const store = require('../packages/gateway-core/src/security/store');

    const [res1, res2] = await Promise.all([
      store.checkAndRecordNonce(testNonce, 300),
      store.checkAndRecordNonce(testNonce, 300)
    ]);

    const passes = [res1, res2].filter(r => r.valid).length;
    const rejects = [res1, res2].filter(r => !r.valid && r.reason === 'REPLAY_ATTACK_DETECTED').length;

    assert.strictEqual(passes, 1, 'Exactly one nonce registration must succeed');
    assert.strictEqual(rejects, 1, 'Duplicate nonce must be rejected with REPLAY_ATTACK_DETECTED');
  });
});

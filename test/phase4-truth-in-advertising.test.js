const test = require('node:test');
const assert = require('node:assert');
const jwksHandler = require('../api/_lib/handlers/jwks');
const dsrHandler = require('../api/_lib/handlers/dsr');
const keysHandler = require('../api/_lib/handlers/keys');
const { setDatabaseClient } = require('../packages/gateway-core/src/security/store');
const { TestPostgresAdapter } = require('../packages/gateway-core/src/security/testDbAdapter');
const { runBenchmark } = require('../scripts/benchmark');

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

test('PHASE 4 ACCEPTANCE: Truth-in-Advertising, JWKS & DSR Compliance', async (t) => {
  const dbAdapter = new TestPostgresAdapter();
  setDatabaseClient(dbAdapter);

  // 4.1 JWKS Endpoint RFC 7517 Conformance
  await t.test('4.1 /.well-known/jwks.json returns standard RFC 7517 Ed25519 JWK set', async () => {
    const req = { method: 'GET', url: '/.well-known/jwks.json', headers: {} };
    const res = mockRes();
    await jwksHandler(req, res);

    assert.strictEqual(res.getStatusCode(), 200);
    const body = res.getBody();
    assert.ok(Array.isArray(body.keys));
    assert.strictEqual(body.keys[0].kty, 'OKP');
    assert.strictEqual(body.keys[0].crv, 'Ed25519');
    assert.strictEqual(body.keys[0].alg, 'EdDSA');
    assert.ok(body.keys[0].x, 'Must contain public key component x');
  });

  // 4.2 Provision Key for DSR Tests
  let testKey;
  await t.test('4.2 Provision key for DSR tests', async () => {
    const req = {
      method: 'POST',
      url: '/api/keys/generate',
      headers: { 'content-type': 'application/json', 'x-real-ip': '192.168.1.1' },
      body: { name: 'DSR Test Key', orgId: 'org_privacy_audit' }
    };
    const res = mockRes();
    await keysHandler(req, res);
    assert.strictEqual(res.getStatusCode(), 200);
    testKey = res.getBody().rawKey;
    assert.ok(testKey);
  });

  // 4.3 DSR Export Endpoint (/api/account/export)
  await t.test('4.3 /api/account/export returns verified org records', async () => {
    const req = {
      method: 'GET',
      url: '/api/account/export',
      headers: { 'x-api-key': testKey }
    };
    const res = mockRes();
    await dsrHandler(req, res);
    assert.strictEqual(res.getStatusCode(), 200);
    const body = res.getBody();
    assert.strictEqual(body.status, 'SUCCESS');
    assert.strictEqual(body.orgId, 'org_privacy_audit');
    assert.ok(Array.isArray(body.auditEvents));
  });

  // 4.4 DSR Deletion Endpoint (/api/account/delete)
  await t.test('4.4 /api/account/delete confirms organization metadata deletion', async () => {
    const req = {
      method: 'POST',
      url: '/api/account/delete',
      headers: { 'x-api-key': testKey }
    };
    const res = mockRes();
    await dsrHandler(req, res);
    assert.strictEqual(res.getStatusCode(), 200);
    const body = res.getBody();
    assert.strictEqual(body.status, 'SUCCESS');
    assert.strictEqual(body.orgId, 'org_privacy_audit');
  });

  // 4.5 Latency Benchmark Execution
  await t.test('4.5 Benchmark script measures empirical latency percentiles', async () => {
    const stats = await runBenchmark(100);
    assert.ok(parseFloat(stats.p50) < 10.0, 'p50 latency must be sub-10ms');
    assert.ok(parseFloat(stats.p99) < 25.0, 'p99 latency must be sub-25ms');
  });
});

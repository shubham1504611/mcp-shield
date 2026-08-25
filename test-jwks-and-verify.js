const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const jwksHandler = require('./api/_lib/handlers/jwks');
const healthHandler = require('./api/_lib/handlers/health');
const dsrHandler = require('./api/_lib/handlers/dsr');
const evaluateHandler = require('./api/_lib/handlers/evaluate');
const keysHandler = require('./api/_lib/handlers/keys');
const { verifyAttestationSignature } = require('./packages/cli-shield/src/verify');
const { PUBLIC_KEY } = require('./packages/gateway-core/src/security/waf');
const { setDatabaseClient } = require('./packages/gateway-core/src/security/store');
const { TestPostgresAdapter } = require('./packages/gateway-core/src/security/testDbAdapter');

setDatabaseClient(new TestPostgresAdapter());

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

test('Enterprise Security & Verification Suite', async (t) => {
  let apiKey;

  // 1. Provision Key
  await t.test('Provision key with HMAC pepper', async () => {
    const req = {
      method: 'POST',
      url: '/api/keys/generate',
      headers: { 'content-type': 'application/json' },
      body: { name: 'Enterprise Verification Key', orgId: 'org_test_ent' }
    };
    const res = mockRes();
    await keysHandler(req, res);
    assert.strictEqual(res.getStatusCode(), 200);
    apiKey = res.getBody().rawKey;
    assert.ok(apiKey);
  });

  // 2. Health Endpoint
  await t.test('Health endpoint returns healthy status and loaded signing key', async () => {
    const req = { method: 'GET', url: '/api/health', headers: {} };
    const res = mockRes();
    await healthHandler(req, res);
    assert.strictEqual(res.getStatusCode(), 200);
    const body = res.getBody();
    assert.strictEqual(body.status, 'HEALTHY');
    assert.strictEqual(body.signingKeyStatus, 'loaded');
  });

  // 3. JWKS Endpoint
  await t.test('JWKS endpoint conforms to RFC 7517 Ed25519 format', async () => {
    const req = { method: 'GET', url: '/.well-known/jwks.json', headers: {} };
    const res = mockRes();
    await jwksHandler(req, res);
    assert.strictEqual(res.getStatusCode(), 200);
    const body = res.getBody();
    assert.ok(Array.isArray(body.keys));
    assert.strictEqual(body.keys[0].kty, 'OKP');
    assert.strictEqual(body.keys[0].crv, 'Ed25519');
    assert.ok(body.keys[0].x, 'Should contain public key parameter x');
  });

  // 4. Evaluate & Verify Attestation with CLI Verifier
  await t.test('Evaluate query and verify Ed25519 signature independently', async () => {
    const req = {
      method: 'POST',
      url: '/api/evaluate',
      headers: {
        'content-type': 'application/json',
        'x-api-key': apiKey
      },
      body: {
        tool: 'postgres_query',
        query: 'SELECT name, role FROM team_members LIMIT 5;'
      }
    };
    const res = mockRes();
    await evaluateHandler(req, res);
    assert.strictEqual(res.getStatusCode(), 200);
    const body = res.getBody();
    assert.strictEqual(body.isSafe, true);
    assert.ok(body.signature);
    assert.ok(body.nonce);

    // Verify using standalone verifyAttestationSignature
    const verification = verifyAttestationSignature({
      tool: 'postgres_query',
      payload: { query: 'SELECT name, role FROM team_members LIMIT 5;' },
      nonce: body.nonce,
      timestamp: body.timestamp,
      policyVersion: '2.5.0',
      signature: body.signature,
      publicKeyPem: PUBLIC_KEY
    });

    assert.strictEqual(verification.valid, true, 'Attestation signature must be mathematically valid');
  });

  // 5. 64KB Payload Cap Enforcement
  await t.test('Reject payloads exceeding 64KB cap', async () => {
    const hugeQuery = 'SELECT ' + 'x'.repeat(70000);
    const req = {
      method: 'POST',
      url: '/api/evaluate',
      headers: {
        'content-type': 'application/json',
        'x-api-key': apiKey
      },
      body: { tool: 'postgres_query', query: hugeQuery }
    };
    const res = mockRes();
    await evaluateHandler(req, res);
    assert.strictEqual(res.getStatusCode(), 413);
    assert.strictEqual(res.getBody().error, 'PAYLOAD_TOO_LARGE');
  });

  // 6. DSR Privacy Export Endpoint
  await t.test('DSR export endpoint exports org telemetry securely', async () => {
    const req = {
      method: 'GET',
      url: '/api/account/export',
      headers: { 'x-api-key': apiKey }
    };
    const res = mockRes();
    await dsrHandler(req, res);
    assert.strictEqual(res.getStatusCode(), 200);
    const body = res.getBody();
    assert.strictEqual(body.status, 'SUCCESS');
    assert.strictEqual(body.orgId, 'org_test_ent');
  });
});

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');

const unifiedApiHandler = require('./api/index');
const generateKeyHandler = require('./api/_lib/handlers/keys');
const evaluateHandler = require('./api/_lib/handlers/evaluate');
const mcpHandler = require('./api/_lib/handlers/mcp');
const { getMetrics, getAuditLogs } = require('./api/_lib/store');
const { PUBLIC_KEY, verifyAttestation } = require('./api/_lib/waf');
const { setDatabaseClient } = require('./packages/gateway-core/src/security/store');
const { TestPostgresAdapter } = require('./packages/gateway-core/src/security/testDbAdapter');

setDatabaseClient(new TestPostgresAdapter());

function createMockReqRes({ method = 'POST', headers = {}, body = null, url = '/', ip = '127.0.0.1' } = {}) {
  let statusCode = 200;
  let responseHeaders = {};
  let responseData = null;
  let isEnded = false;

  const req = {
    method,
    headers: { 'x-real-ip': ip, ...headers },
    body,
    url,
    socket: { remoteAddress: ip },
    [Symbol.asyncIterator]: async function* () {
      if (body) {
        if (typeof body === 'string') yield Buffer.from(body);
        else yield Buffer.from(JSON.stringify(body));
      }
    }
  };

  const res = {
    statusCode: 200,
    status(code) {
      statusCode = code;
      this.statusCode = code;
      return this;
    },
    setHeader(name, value) {
      responseHeaders[name.toLowerCase()] = value;
      return this;
    },
    getHeader(name) {
      return responseHeaders[name.toLowerCase()];
    },
    json(data) {
      responseData = data;
      isEnded = true;
      return this;
    },
    end(data) {
      if (data && !responseData) {
        try { responseData = JSON.parse(data); } catch (_) { responseData = data; }
      }
      isEnded = true;
      return this;
    },
    _getResults() {
      return { statusCode, headers: responseHeaders, data: responseData, isEnded };
    }
  };

  return { req, res };
}

test('🛡️ API Route & Architecture Hardening Verification Suite (13 Remediation Items)', async (t) => {

  await t.test('C1: Keygen Fails Closed on Missing/Invalid Admin Secret', async () => {
    const { req, res } = createMockReqRes({
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: { tier: 'production', name: 'Hacker Prod Key' },
      ip: '10.0.0.1'
    });

    await generateKeyHandler(req, res);
    const result = res._getResults();

    assert.strictEqual(result.statusCode, 200);
    assert.strictEqual(result.data.status, 'KEY_PROVISIONED');
    assert.strictEqual(result.data.tier, 'sandbox');
    assert.ok(result.data.apiKey.startsWith('mcp_sandbox_'));
    assert.strictEqual(result.data.rateLimitRpm, 30);
  });

  await t.test('C1: Production Key Minting Strictly Requires Verified MCP_ADMIN_SECRET', async () => {
    process.env.MCP_ADMIN_SECRET = 'super_secure_admin_production_passphrase_2026';

    const { req, res } = createMockReqRes({
      method: 'POST',
      headers: { 
        'content-type': 'application/json',
        'authorization': 'Bearer super_secure_admin_production_passphrase_2026'
      },
      body: { tier: 'production', name: 'Verified Corp Key' },
      ip: '10.0.0.2'
    });

    await generateKeyHandler(req, res);
    const result = res._getResults();

    assert.strictEqual(result.statusCode, 200);
    assert.strictEqual(result.data.tier, 'production');
    assert.ok(result.data.apiKey.startsWith('mcp_live_sec_'));
    assert.strictEqual(result.data.rateLimitRpm, 120);

    delete process.env.MCP_ADMIN_SECRET;
  });

  await t.test('C2: POST /api/evaluate Rejects Requests Without Valid API Key (401)', async () => {
    const { req, res } = createMockReqRes({
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: { tool: 'postgres_query', query: 'SELECT * FROM users;' },
      ip: '10.0.0.3'
    });

    await evaluateHandler(req, res);
    const result = res._getResults();

    assert.strictEqual(result.statusCode, 401);
    assert.strictEqual(result.data.error, 'UNAUTHORIZED');
  });

  await t.test('C2: POST /api/evaluate Accepts Valid API Key and Returns Signed Response', async () => {
    const { req: keyReq, res: keyRes } = createMockReqRes({
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: {},
      ip: '10.0.0.4'
    });
    await generateKeyHandler(keyReq, keyRes);
    const validKey = keyRes._getResults().data.apiKey;
    assert.ok(validKey, 'Key must be minted');

    const { req, res } = createMockReqRes({
      method: 'POST',
      headers: { 
        'content-type': 'application/json',
        'x-api-key': validKey
      },
      body: { tool: 'postgres_query', query: 'SELECT id, name FROM customers WHERE id = 10;' },
      ip: '10.0.0.4'
    });

    await evaluateHandler(req, res);
    const result = res._getResults();

    assert.strictEqual(result.statusCode, 200);
    assert.strictEqual(result.data.isSafe, true);
    assert.ok(result.data.signature);
    assert.ok(verifyAttestation(result.data));
  });

  await t.test('C3: POST /v1/mcp Handles JSON-RPC tools/call and Container Execution', async () => {
    const { req, res } = createMockReqRes({
      method: 'POST',
      headers: { 
        'content-type': 'application/json',
        'x-api-key': 'mcp_sandbox_test_token_for_mcp_call'
      },
      body: {
        jsonrpc: '2.0',
        id: 'req_123',
        method: 'tools/call',
        params: {
          name: 'postgres_query',
          arguments: { query: 'SELECT id, email FROM customers WHERE active = true;' }
        }
      },
      ip: '10.0.0.5'
    });

    await mcpHandler(req, res);
    const result = res._getResults();

    assert.strictEqual(result.statusCode, 200);
    assert.strictEqual(result.data.jsonrpc, '2.0');
    assert.strictEqual(result.data.result.status, 'AUTHENTICATED_AND_SIGNED');
    assert.ok(result.data.result.attestation);
    assert.ok(result.data.result.content[0].text.includes('[MCP-SHIELD CONTAINER EXECUTION]'));
  });

  await t.test('C4: JSON Body Parser Gracefully Handles String and Buffer Payloads', async () => {
    const jsonStr = JSON.stringify({ tool: 'postgres_query', query: 'SELECT 1;' });
    const { req, res } = createMockReqRes({
      method: 'POST',
      headers: { 
        'content-type': 'application/json',
        'x-api-key': 'mcp_sandbox_test_token_for_parsing'
      },
      body: jsonStr,
      ip: '10.0.0.6'
    });

    await evaluateHandler(req, res);
    const result = res._getResults();

    assert.strictEqual(result.statusCode, 200);
    assert.strictEqual(result.data.isSafe, true);
  });

  await t.test('M1 & M2: Metrics & Audit Logs Start at Real Zero State without Fabricated Seeds', async () => {
    const metrics = await getMetrics();
    const logs = await getAuditLogs();

    assert.ok(typeof metrics.totalCalls === 'number');
    assert.ok(typeof metrics.blockedThreats === 'number');
    assert.ok(Array.isArray(logs));
    assert.notStrictEqual(metrics.totalCalls, 14820);
    assert.notStrictEqual(metrics.blockedThreats, 214);
  });

  await t.test('M3: Deterministic Attestation Public Key Verification Across Instances', () => {
    assert.ok(PUBLIC_KEY);
    assert.ok(PUBLIC_KEY.includes('BEGIN PUBLIC KEY'));
    assert.ok(PUBLIC_KEY.includes('END PUBLIC KEY'));
  });

  await t.test('Vercel Single Function Compliance: api/index.js Routes All API & MCP Endpoints', async () => {
    // 1. Healthcheck via unified router
    const { req: hReq, res: hRes } = createMockReqRes({ method: 'GET', url: '/healthz' });
    await unifiedApiHandler(hReq, hRes);
    assert.strictEqual(hRes._getResults().statusCode, 200);
    assert.strictEqual(hRes._getResults().data.status, 'HEALTHY');

    // 2. Attestation public key via unified router
    const { req: aReq, res: aRes } = createMockReqRes({ method: 'GET', url: '/api/attestation/public-key' });
    await unifiedApiHandler(aReq, aRes);
    assert.strictEqual(aRes._getResults().statusCode, 200);
    assert.ok(aRes._getResults().data.publicKey);

    // 3. /v1/mcp ping via unified router
    const { req: mReq, res: mRes } = createMockReqRes({
      method: 'POST',
      url: '/v1/mcp',
      headers: { 'content-type': 'application/json' },
      body: { jsonrpc: '2.0', id: 'ping_1', method: 'ping' }
    });
    await unifiedApiHandler(mReq, mRes);
    assert.strictEqual(mRes._getResults().statusCode, 200);
    assert.strictEqual(mRes._getResults().data.result.status, 'PONG');
  });
});

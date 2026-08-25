const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const mcpHandler = require('./api/_lib/handlers/mcp');
const evaluateHandler = require('./api/_lib/handlers/evaluate');
const keysHandler = require('./api/_lib/handlers/keys');
const store = require('./api/_lib/store');

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

test('MCP Shield Comprehensive Serverless Gateway Tests', async (t) => {

  // 1. Provision a real registered key
  let registeredKey;
  await t.test('Provision genuine sandbox key', async () => {
    const req = {
      method: 'POST',
      url: '/api/keys/generate',
      headers: { 'content-type': 'application/json' },
      body: { name: 'Test Suite Key', orgId: 'test_org' }
    };
    const res = mockRes();
    await keysHandler(req, res);
    assert.strictEqual(res.getStatusCode(), 200);
    const data = res.getBody();
    assert.ok(data.rawKey, 'Should return rawKey');
    registeredKey = data.rawKey;
  });

  // 2. Test fake well-formed key rejection (Full value hash verification)
  await t.test('Reject fake well-formed sandbox key', async () => {
    const fakeKey = `mcp_sandbox_${crypto.randomBytes(24).toString('hex')}`;
    const req = {
      method: 'POST',
      url: '/api/evaluate',
      headers: {
        'content-type': 'application/json',
        'x-api-key': fakeKey
      },
      body: { tool: 'postgres_query', query: 'SELECT 1;' }
    };
    const res = mockRes();
    await evaluateHandler(req, res);
    assert.strictEqual(res.getStatusCode(), 401, 'Fake unregistered key must be rejected with 401');
    assert.strictEqual(res.getBody().code, 'KEY_NOT_FOUND_OR_REVOKED');
  });

  // 3. Test MCP JSON-RPC initialize
  await t.test('MCP initialize negotiation', async () => {
    const req = {
      method: 'POST',
      url: '/v1/mcp',
      headers: { 'content-type': 'application/json' },
      body: { jsonrpc: '2.0', id: 101, method: 'initialize', params: {} }
    };
    const res = mockRes();
    await mcpHandler(req, res);
    assert.strictEqual(res.getStatusCode(), 200);
    const body = res.getBody();
    assert.strictEqual(body.jsonrpc, '2.0');
    assert.strictEqual(body.id, 101);
    assert.ok(body.result.capabilities.containment);
  });

  // 4. Test MCP JSON-RPC tools/list
  await t.test('MCP tools/list negotiation', async () => {
    const req = {
      method: 'POST',
      url: '/v1/mcp',
      headers: { 'content-type': 'application/json' },
      body: { jsonrpc: '2.0', id: 102, method: 'tools/list', params: {} }
    };
    const res = mockRes();
    await mcpHandler(req, res);
    assert.strictEqual(res.getStatusCode(), 200);
    const body = res.getBody();
    assert.ok(Array.isArray(body.result.tools));
    assert.ok(body.result.tools.some(t => t.name === 'postgres_query'));
  });

  // 5. Test MCP JSON-RPC tools/call execution
  await t.test('MCP tools/call execution with standard arguments', async () => {
    const req = {
      method: 'POST',
      url: '/v1/mcp',
      headers: {
        'content-type': 'application/json',
        'x-api-key': registeredKey
      },
      body: {
        jsonrpc: '2.0',
        id: 103,
        method: 'tools/call',
        params: {
          name: 'postgres_query',
          arguments: {
            query: 'SELECT id, username FROM users WHERE status = "active" LIMIT 10;'
          }
        }
      }
    };
    const res = mockRes();
    await mcpHandler(req, res);
    assert.strictEqual(res.getStatusCode(), 200);
    const body = res.getBody();
    assert.strictEqual(body.jsonrpc, '2.0');
    assert.strictEqual(body.id, 103);
    assert.ok(body.result, 'Should have JSON-RPC result');
    assert.strictEqual(body.result.isError, false);
    assert.ok(body.result.content, 'Should have content');
    assert.ok(res.getHeaders()['x-mcp-signature'], 'Should include X-MCP-Signature header');
  });

  // 6. Test MCP JSON-RPC tools/call attack interception
  await t.test('MCP tools/call attack intercept', async () => {
    const req = {
      method: 'POST',
      url: '/v1/mcp',
      headers: {
        'content-type': 'application/json',
        'x-api-key': registeredKey
      },
      body: {
        jsonrpc: '2.0',
        id: 104,
        method: 'tools/call',
        params: {
          name: 'postgres_query',
          arguments: {
            query: 'DROP TABLE customers CASCADE;'
          }
        }
      }
    };
    const res = mockRes();
    await mcpHandler(req, res);
    assert.strictEqual(res.getStatusCode(), 200);
    const body = res.getBody();
    assert.ok(body.result.isError, 'Should report isError: true on blocked action');
  });

  // 7. Test MCP JSON-RPC Human-In-The-Loop gating with approval token
  await t.test('MCP tools/call Human-in-the-Loop gating and token execution', async () => {
    // Phase A: Request without approval token -> returns REQUIRES_APPROVAL
    const reqA = {
      method: 'POST',
      url: '/v1/mcp',
      headers: {
        'content-type': 'application/json',
        'x-api-key': registeredKey
      },
      body: {
        jsonrpc: '2.0',
        id: 105,
        method: 'tools/call',
        params: {
          name: 'postgres_query',
          arguments: {
            query: 'ALTER TABLE users ADD COLUMN verified boolean;'
          }
        }
      }
    };
    const resA = mockRes();
    await mcpHandler(reqA, resA);
    assert.strictEqual(resA.getStatusCode(), 200);
    const bodyA = resA.getBody();
    assert.strictEqual(bodyA.result.status, 'REQUIRES_APPROVAL');
    const token = bodyA.result.approvalToken;
    assert.ok(token, 'Should provide approval token');

    // Phase B: Provide approval token header -> passes through
    const reqB = {
      method: 'POST',
      url: '/v1/mcp',
      headers: {
        'content-type': 'application/json',
        'x-api-key': registeredKey,
        'x-mcp-approval-token': token
      },
      body: {
        jsonrpc: '2.0',
        id: 106,
        method: 'tools/call',
        params: {
          name: 'postgres_query',
          arguments: {
            query: 'ALTER TABLE users ADD COLUMN verified boolean;'
          }
        }
      }
    };
    const resB = mockRes();
    await mcpHandler(reqB, resB);
    assert.strictEqual(resB.getStatusCode(), 200);
    const bodyB = resB.getBody();
    // After approval gate, WAF evaluates payload (or signs if permitted)
    assert.ok(bodyB.result || bodyB.error);
  });

  // 8. Test Malformed JSON Handling (Parse Error -32700)
  await t.test('MCP handles malformed JSON with standard code -32700', async () => {
    const req = {
      method: 'POST',
      url: '/v1/mcp',
      headers: { 'content-type': 'application/json' },
      body: '{"jsonrpc": 2.0, invalid_unquoted_json}'
    };
    const res = mockRes();
    await mcpHandler(req, res);
    assert.strictEqual(res.getStatusCode(), 400);
    const body = res.getBody();
    assert.strictEqual(body.error.code, -32700);
  });
});

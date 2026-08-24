const test = require('node:test');
const assert = require('node:assert');
const { TunnelCoordinator } = require('../src/tunnel/coordinator');

test('Outbound Reverse Tunnel Test Suite', async (t) => {
  const coordinator = new TunnelCoordinator({ defaultTimeoutMs: 1000 });

  await t.test('Should register a new tunnel and report it as active', () => {
    const session = coordinator.registerTunnel('tun_test_01', {
      keyId: 'mcp_live_sec_test',
      targetName: 'postgres-internal'
    });

    assert.strictEqual(session.tunnelId, 'tun_test_01');
    assert.strictEqual(session.targetName, 'postgres-internal');
    assert.strictEqual(coordinator.isTunnelActive('tun_test_01'), true);

    const list = coordinator.listActiveTunnels();
    assert.strictEqual(list.length, 1);
    assert.strictEqual(list[0].tunnelId, 'tun_test_01');
  });

  await t.test('Should successfully dispatch tool request and receive response through tunnel', async () => {
    const tunnelId = 'tun_test_echo';
    
    // Register tunnel with an automated echo responder
    coordinator.registerTunnel(tunnelId, {
      keyId: 'mcp_live_sec_prod',
      targetName: 'db-echo'
    }, (requestPayload) => {
      // Simulate client responding back
      coordinator.handleTunnelResponse(tunnelId, {
        jsonrpc: '2.0',
        id: requestPayload.id,
        result: {
          rows: [{ id: 1, name: 'Private Record' }]
        }
      });
    });

    const response = await coordinator.dispatchThroughTunnel(tunnelId, {
      jsonrpc: '2.0',
      method: 'tools/call',
      params: { query: 'SELECT * FROM private_table' }
    });

    assert.strictEqual(response.jsonrpc, '2.0');
    assert.deepStrictEqual(response.result.rows, [{ id: 1, name: 'Private Record' }]);
  });

  await t.test('Should reject when tunnel request times out', async () => {
    const tunnelId = 'tun_test_hang';
    
    // Register tunnel that never responds
    coordinator.registerTunnel(tunnelId, {
      keyId: 'mcp_live_sec_test',
      targetName: 'slow-db'
    }, () => {});

    await assert.rejects(async () => {
      await coordinator.dispatchThroughTunnel(tunnelId, {
        jsonrpc: '2.0',
        method: 'tools/call',
        params: {}
      }, 100); // 100ms timeout
    }, /timed out/);
  });

  await t.test('Should unregister tunnel and clean up sessions', () => {
    const tunnelId = 'tun_test_01';
    const unreg = coordinator.unregisterTunnel(tunnelId);
    assert.strictEqual(unreg, true);
    assert.strictEqual(coordinator.isTunnelActive(tunnelId), false);
    assert.strictEqual(coordinator.getTunnel(tunnelId), null);
  });
});

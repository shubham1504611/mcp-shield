const test = require('node:test');
const assert = require('node:assert');
const { SecurityDoctor } = require('../src/doctor');

test('CLI Security Doctor & Auto-Patching Test Suite', async (t) => {
  const doctor = new SecurityDoctor();

  const mockVulnerableConfig = {
    mcpServers: {
      'raw-postgres': {
        command: 'npx',
        args: ['-y', '@modelcontextprotocol/server-postgres', 'postgresql://user:secret123@localhost:5432/mydb']
      },
      'raw-filesystem': {
        command: 'npx',
        args: ['-y', '@modelcontextprotocol/server-filesystem', '/']
      },
      'already-shielded': {
        command: 'npx',
        args: ['-y', 'mcp-shield', 'wrap', '--target', 'npx @modelcontextprotocol/server-github']
      }
    }
  };

  await t.test('Should detect unshielded tools, credentials, and excessive privileges', () => {
    const report = doctor.diagnose(mockVulnerableConfig);

    assert.strictEqual(report.status, 'VULNERABILITIES_FOUND');
    assert.strictEqual(report.totalServers, 3);
    assert.strictEqual(report.shieldedCount, 1);
    assert.strictEqual(report.vulnerableCount, 2);
    assert.ok(report.score < 50);

    const credIssue = report.issues.find(i => i.type === 'HARDCODED_CREDENTIAL');
    assert.ok(credIssue);
    assert.strictEqual(credIssue.serverName, 'raw-postgres');

    const fsIssue = report.issues.find(i => i.type === 'EXCESSIVE_FILESYSTEM_PRIVILEGE');
    assert.ok(fsIssue);
    assert.strictEqual(fsIssue.serverName, 'raw-filesystem');
  });

  await t.test('Should successfully auto-patch vulnerable configurations with mcp-shield wrappers', () => {
    const { patchedConfig, patchedCount } = doctor.autoPatch(mockVulnerableConfig);

    assert.strictEqual(patchedCount, 2);

    const postDoctor = doctor.diagnose(patchedConfig);
    assert.strictEqual(postDoctor.shieldedCount, 3);
    assert.strictEqual(postDoctor.vulnerableCount, 0);

    // Verify raw-postgres command is wrapped
    const wrappedArgs = patchedConfig.mcpServers['raw-postgres'].args;
    assert.strictEqual(wrappedArgs[1], 'mcp-shield');
    assert.strictEqual(wrappedArgs[2], 'wrap');
  });

  await t.test('Should report 100% HEALTHY score on fully shielded config', () => {
    const fullyShielded = {
      mcpServers: {
        'shielded-db': {
          command: 'npx',
          args: ['-y', 'mcp-shield', 'wrap', '--target', 'npx server-postgres']
        }
      }
    };

    const report = doctor.diagnose(fullyShielded);
    assert.strictEqual(report.status, 'HEALTHY');
    assert.strictEqual(report.score, 100);
    assert.strictEqual(report.issues.length, 0);
  });
});

const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const fs = require('fs');
const { SecurityWaf } = require('../packages/gateway-core/src/security/waf');

const safeCorpus = JSON.parse(fs.readFileSync(path.join(__dirname, 'corpora', 'safe_queries.json'), 'utf8'));
const adversarialCorpus = JSON.parse(fs.readFileSync(path.join(__dirname, 'corpora', 'adversarial_queries.json'), 'utf8'));

test('PHASE 3 ACCEPTANCE: WAF Allowlist Mode & Bypass Regression Vectors', async (t) => {

  // 3.1 Allowlist Mode: Safe Corpus Evaluation
  await t.test('3.1 Allowlist Mode: All queries in safe corpus pass', () => {
    const waf = new SecurityWaf({ mode: 'allowlist' });
    for (const query of safeCorpus) {
      const res = waf.inspectToolCall('postgres_query', { query });
      assert.strictEqual(res.isSafe, true, `Expected safe query to pass: ${query}`);
    }
  });

  // 3.2 Allowlist Mode: Adversarial Corpus Interception
  await t.test('3.2 Allowlist Mode: All queries in adversarial corpus are blocked', () => {
    const waf = new SecurityWaf({ mode: 'allowlist' });
    for (const query of adversarialCorpus) {
      const res = waf.inspectToolCall('postgres_query', { query });
      assert.strictEqual(res.isSafe, false, `Expected adversarial query to be blocked: ${query}`);
    }
  });

  // 3.3 Configured Table Allowlist Check
  await t.test('3.3 Table Allowlist: Restricts queries strictly to whitelisted tables', () => {
    const waf = new SecurityWaf({
      mode: 'allowlist',
      allowedTables: ['users', 'products']
    });

    const allowed = waf.inspectToolCall('postgres_query', { query: 'SELECT id, username FROM users WHERE id = 1;' });
    assert.strictEqual(allowed.isSafe, true);

    const forbidden = waf.inspectToolCall('postgres_query', { query: 'SELECT * FROM salaries WHERE role = "CEO";' });
    assert.strictEqual(forbidden.isSafe, false);
    assert.strictEqual(forbidden.rule, 'TABLE_NOT_IN_ALLOWLIST');
  });

  // 3.4 Bypass Regression: Nested Block Comments
  await t.test('3.4 Bypass Regression: Nested block comments /* /* ... */ */', () => {
    const waf = new SecurityWaf();
    const attack = '/* level 1 /* level 2 */ */ DROP TABLE audit_logs;';
    const res = waf.inspectToolCall('postgres_query', { query: attack });
    assert.strictEqual(res.isSafe, false);
  });

  // 3.5 Bypass Regression: Dollar-Quoting Obfuscation
  await t.test('3.5 Bypass Regression: Dollar-quoting obfuscation ($$ ... $$)', () => {
    const waf = new SecurityWaf();
    const attack = 'DO $$ BEGIN EXECUTE \'DROP TABLE secrets\'; END $$;';
    const res = waf.inspectToolCall('postgres_query', { query: attack });
    assert.strictEqual(res.isSafe, false);
  });

  // 3.6 Bypass Regression: Null Byte Injection Smuggling (\u0000)
  await t.test('3.6 Bypass Regression: Null byte smuggling', () => {
    const waf = new SecurityWaf();
    const attack = 'SELECT * FROM users WHERE 1\u0000=1;';
    const res = waf.inspectToolCall('postgres_query', { query: attack });
    assert.strictEqual(res.isSafe, false);
  });

  // 3.7 Strict Input Size Cap (32KB Limit)
  await t.test('3.7 Strict Input Size Cap: Rejects payloads > 32KB', () => {
    const waf = new SecurityWaf();
    const oversize = 'SELECT ' + 'A'.repeat(35000);
    const res = waf.inspectToolCall('postgres_query', { query: oversize });
    assert.strictEqual(res.isSafe, false);
    assert.strictEqual(res.rule, 'PAYLOAD_TOO_LARGE');
  });

  // 3.8 Prototype Pollution Defense
  await t.test('3.8 Prototype Pollution Defense: Strips __proto__ attacks', () => {
    const waf = new SecurityWaf();
    const pollutedPayload = JSON.parse('{"__proto__": {"admin": true}, "query": "SELECT 1;"}');
    const res = waf.inspectToolCall('postgres_query', pollutedPayload);
    assert.strictEqual(res.isSafe, true);
    assert.strictEqual(({}).admin, undefined, 'Object prototype must not be polluted');
  });
});

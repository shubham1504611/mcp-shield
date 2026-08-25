const test = require('node:test');
const assert = require('node:assert');
const { SecurityWaf } = require('../packages/gateway-core/src/security/waf');

const seedMutations = [
  'SELECT 1',
  'DROP TABLE users',
  'DELETE FROM accounts WHERE 1=1',
  'ALTER TABLE profiles ADD COLUMN admin bool',
  'COPY secrets TO PROGRAM "/bin/sh"',
  'UNION SELECT username, password FROM users'
];

function mutate(str, iteration) {
  switch (iteration % 7) {
    case 0:
      return str + ' /*' + '/*nested*/'.repeat(20) + '*/';
    case 1:
      return str.split('').join('\u200B'); // zero-width
    case 2:
      return str.split('').join('\u0000'); // null bytes
    case 3:
      return '$_$' + str + '$_$';
    case 4:
      return str.replace(/ /g, '/**/'.repeat(5));
    case 5:
      return str + ' ' + 'A'.repeat(5000);
    case 6:
      return str.split('').map(c => '\\u00' + c.charCodeAt(0).toString(16)).join('');
    default:
      return str;
  }
}

test('PHASE 3 FUZZ HARNESS: Adversarial Mutation & Catastrophic Backtracking Stress', async (t) => {
  const waf = new SecurityWaf({ mode: 'blocklist' });
  const allowWaf = new SecurityWaf({ mode: 'allowlist' });

  await t.test('Fuzz Harness runs 100 mutated payload permutations with zero crashes', () => {
    let completed = 0;

    for (let i = 0; i < 100; i++) {
      const seed = seedMutations[i % seedMutations.length];
      const mutatedPayload = mutate(seed, i);

      // Blocklist test
      const resBlock = waf.inspectToolCall('postgres_query', { query: mutatedPayload });
      assert.ok(typeof resBlock.isSafe === 'boolean', 'Result isSafe must be boolean');

      // Allowlist test
      const resAllow = allowWaf.inspectToolCall('postgres_query', { query: mutatedPayload });
      assert.ok(typeof resAllow.isSafe === 'boolean', 'Allowlist isSafe must be boolean');

      completed++;
    }

    assert.strictEqual(completed, 100, 'All 100 fuzz mutations must complete cleanly');
  });
});

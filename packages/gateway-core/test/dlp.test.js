const test = require('node:test');
const assert = require('node:assert');
const { SecurityWaf } = require('../src/security/waf');

test('Enterprise DLP & Custom Regex Policy Test Suite', async (t) => {
  const waf = new SecurityWaf();

  await t.test('Should intercept and block Social Security Numbers (SSN)', () => {
    const res = waf.inspectToolCall('postgres_query', {
      query: 'SELECT * FROM applicants WHERE ssn = "123-45-6789"'
    });

    assert.strictEqual(res.isSafe, false);
    assert.strictEqual(res.rule, 'DLP_SSN_DETECTED');
    assert.ok(res.reason.includes('Social Security Number'));
  });

  await t.test('Should intercept and block Credit Card Numbers', () => {
    const res = waf.inspectToolCall('payment_api', {
      card: '4111222233334444'
    });

    assert.strictEqual(res.isSafe, false);
    assert.strictEqual(res.rule, 'DLP_CREDIT_CARD_DETECTED');
  });

  await t.test('Should intercept and block Cryptographic Private Key blocks', () => {
    const res = waf.inspectToolCall('filesystem_write', {
      content: '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...'
    });

    assert.strictEqual(res.isSafe, false);
    assert.strictEqual(res.rule, 'DLP_PRIVATE_KEY_DETECTED');
  });

  await t.test('Should support adding and enforcing custom Regex rules', () => {
    const customWaf = new SecurityWaf();
    customWaf.addCustomRule('INTERNAL_EMP_ID', /\bEMP-\d{5}\b/);

    const blocked = customWaf.inspectToolCall('slack_notify', {
      text: 'Querying records for EMP-98214'
    });

    assert.strictEqual(blocked.isSafe, false);
    assert.strictEqual(blocked.rule, 'CUSTOM_RULE_INTERNAL_EMP_ID');

    // Remove custom rule
    customWaf.removeRule('INTERNAL_EMP_ID');
    const allowed = customWaf.inspectToolCall('slack_notify', {
      text: 'Querying records for EMP-98214'
    });
    assert.strictEqual(allowed.isSafe, true);
  });

  await t.test('Should support adding and blocking custom protected keywords/tables', () => {
    const customWaf = new SecurityWaf();
    customWaf.addBlockedKeyword('payroll_salaries');

    const blocked = customWaf.inspectToolCall('postgres_query', {
      query: 'SELECT * FROM payroll_salaries WHERE department = "exec"'
    });

    assert.strictEqual(blocked.isSafe, false);
    assert.strictEqual(blocked.rule, 'CUSTOM_KEYWORD_BLOCKED');
  });
});

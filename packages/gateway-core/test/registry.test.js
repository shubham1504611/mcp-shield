const test = require('node:test');
const assert = require('node:assert');
const { getAllTools, getToolById, getToolsByCategory } = require('../src/registry/tools');

test('Community Tool Registry Test Suite', async (t) => {
  await t.test('Should return all verified community tools', () => {
    const tools = getAllTools();
    assert.ok(Array.isArray(tools));
    assert.ok(tools.length >= 8);

    const postgres = tools.find(t => t.id === 'postgres');
    assert.ok(postgres);
    assert.strictEqual(postgres.name, 'PostgreSQL Database Server');
    assert.strictEqual(postgres.securityVerified, true);
    assert.strictEqual(postgres.riskRating, 'HIGH_MUTATION');
  });

  await t.test('Should fetch individual tool by id', () => {
    const github = getToolById('github');
    assert.ok(github);
    assert.strictEqual(github.id, 'github');
    assert.strictEqual(github.category, 'Developer Tools');
    assert.ok(github.shieldCommand.includes('wrap'));
  });

  await t.test('Should filter tools by category', () => {
    const dbs = getToolsByCategory('Databases');
    assert.ok(dbs.length >= 1);
    assert.ok(dbs.every(d => d.category === 'Databases'));

    const web = getToolsByCategory('Web & Search');
    assert.ok(web.length >= 2);
    assert.ok(web.some(w => w.id === 'brave-search'));
    assert.ok(web.some(w => w.id === 'puppeteer'));
  });

  await t.test('Should return null for non-existent tool', () => {
    const unknown = getToolById('non_existent_tool_123');
    assert.strictEqual(unknown, null);
  });
});

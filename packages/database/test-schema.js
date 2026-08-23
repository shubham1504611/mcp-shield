/**
 * Test Suite: Database Schema & Migration Verifier
 * Validates the PostgreSQL Master Schema definitions, Table structures,
 * Foreign Keys, Constraints, Indexes, and RLS policies.
 */

const fs = require('fs');
const path = require('path');
const assert = require('assert');

console.log('🧪 Starting Phase 1: Database Schema Automated Verification...\n');

const schemaPath = path.join(__dirname, 'schema.sql');
assert.ok(fs.existsSync(schemaPath), 'Error: schema.sql not found at expected path.');

const sqlContent = fs.readFileSync(schemaPath, 'utf8');

// 1. Verify Core Tables
const expectedTables = [
  'organizations',
  'organization_members',
  'api_keys',
  'tools',
  'tool_policies',
  'audit_logs',
  'marketplace_transactions'
];

expectedTables.forEach((table) => {
  const regex = new RegExp(`CREATE\\s+TABLE\\s+(IF\\s+NOT\\s+EXISTS\\s+)?${table}\\s*\\(`, 'i');
  assert.ok(regex.test(sqlContent), `Assertion Failed: Table '${table}' is missing from schema.`);
  console.log(`  ✓ Table '${table}' structure verified`);
});

// 2. Verify Primary Keys & UUID Generation
expectedTables.forEach((table) => {
  const pkRegex = new RegExp(`${table}[\\s\\S]*?id\\s+UUID\\s+PRIMARY\\s+KEY`, 'i');
  assert.ok(pkRegex.test(sqlContent), `Assertion Failed: Table '${table}' lacks UUID PRIMARY KEY.`);
});
console.log('  ✓ UUID Primary Key constraints verified across all 7 tables');

// 3. Verify Foreign Key Cascade Rules
const expectedFks = [
  { table: 'organization_members', regex: /org_id\s+UUID\s+REFERENCES\s+organizations\(id\)\s+ON\s+DELETE\s+CASCADE/i },
  { table: 'api_keys', regex: /org_id\s+UUID\s+REFERENCES\s+organizations\(id\)\s+ON\s+DELETE\s+CASCADE/i },
  { table: 'tools', regex: /org_id\s+UUID\s+REFERENCES\s+organizations\(id\)\s+ON\s+DELETE\s+CASCADE/i },
  { table: 'tool_policies', regex: /org_id\s+UUID\s+REFERENCES\s+organizations\(id\)\s+ON\s+DELETE\s+CASCADE/i },
  { table: 'tool_policies', regex: /tool_id\s+UUID\s+REFERENCES\s+tools\(id\)\s+ON\s+DELETE\s+CASCADE/i },
  { table: 'audit_logs', regex: /org_id\s+UUID\s+REFERENCES\s+organizations\(id\)\s+ON\s+DELETE\s+CASCADE/i },
  { table: 'marketplace_transactions', regex: /caller_org_id\s+UUID\s+REFERENCES\s+organizations\(id\)/i },
  { table: 'marketplace_transactions', regex: /tool_id\s+UUID\s+REFERENCES\s+tools\(id\)/i }
];

expectedFks.forEach(({ table, regex }) => {
  assert.ok(
    regex.test(sqlContent),
    `Assertion Failed: Foreign key constraint matching '${regex}' missing in '${table}'.`
  );
});
console.log('  ✓ Foreign key cascade and referential integrity constraints verified');

// 4. Verify Performance Indexes
const expectedIndexes = [
  'idx_orgs_slug',
  'idx_api_keys_hash',
  'idx_audit_logs_org_time',
  'idx_audit_logs_blocked'
];

expectedIndexes.forEach((idx) => {
  const idxRegex = new RegExp(`CREATE\\s+INDEX\\s+(IF\\s+NOT\\s+EXISTS\\s+)?${idx}`, 'i');
  assert.ok(idxRegex.test(sqlContent), `Assertion Failed: Index '${idx}' is missing.`);
  console.log(`  ✓ Performance Index '${idx}' verified`);
});

// 5. Verify Row-Level Security (RLS) Enablement
expectedTables.forEach((table) => {
  const rlsRegex = new RegExp(`ALTER\\s+TABLE\\s+${table}\\s+ENABLE\\s+ROW\\s+LEVEL\\s+SECURITY`, 'i');
  assert.ok(rlsRegex.test(sqlContent), `Assertion Failed: RLS is not enabled for table '${table}'.`);
});
// 6. Verify Analytical Dashboard Views
const expectedViews = [
  'v_org_dashboard_kpis',
  'v_org_threat_breakdown'
];

expectedViews.forEach((view) => {
  const viewRegex = new RegExp(`CREATE\\s+(OR\\s+REPLACE\\s+)?VIEW\\s+${view}\\s+AS`, 'i');
  assert.ok(viewRegex.test(sqlContent), `Assertion Failed: Analytical View '${view}' is missing.`);
  console.log(`  ✓ Analytical Dashboard View '${view}' verified`);
});

console.log('\n======================================================');
console.log('🎉 PHASE 1 TEST SUITE PASSED: 100% Schema & View Validations Passed');
console.log('======================================================\n');

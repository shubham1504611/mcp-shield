#!/usr/bin/env node

/**
 * MCP Shield CLI Executable (npx mcp-shield)
 */

const { discoverMcpConfigs } = require('../src/scanner');
const { LocalShieldRunner } = require('../src/runner');

console.log(`
\x1b[36m   __  __  ____ ____     ____  _     _ _____ _     ____  \x1b[0m
\x1b[36m  |  \\/  |/ ___|  _ \\   / ___|| |__ (_) ____| |   |  _ \\ \x1b[0m
\x1b[36m  | |\\/| | |   | |_) |  \\___ \\| '_ \\| |  _| | |   | | | |\x1b[0m
\x1b[36m  | |  | | |___|  __/    ___) | | | | | |___| |___| |_| |\x1b[0m
\x1b[36m  |_|  |_|\\____|_|      |____/|_| |_|_|_____|_____|____/ \x1b[0m
\x1b[90m  Zero-Trust Security WAF & Attestation for AI Agents v1.0.0\x1b[0m
`);

console.log('🔍 Scanning local IDE environments for MCP configs...');
const discovered = discoverMcpConfigs();

if (discovered.length === 0) {
  console.log('\x1b[33mℹ No existing MCP configs found. Starting standalone protection proxy...\x1b[0m');
} else {
  console.log(`\x1b[32m✓ Found ${discovered.length} MCP configuration files:\x1b[0m`);
  discovered.forEach((d) => {
    console.log(`  • ${d.filePath} (${d.serverCount} active servers: ${d.serverNames.join(', ') || 'none'})`);
  });
}

const runner = new LocalShieldRunner({ port: 8080 });
runner.start((port) => {
  console.log(`\n\x1b[32m🛡️  MCP Shield is actively protecting on http://127.0.0.1:${port}\x1b[0m`);
  console.log(`📊 Live Visual HUD: \x1b[34mhttp://127.0.0.1:${port}/live\x1b[0m`);
  console.log(`\x1b[90mPress Ctrl+C to stop.\x1b[0m\n`);
});

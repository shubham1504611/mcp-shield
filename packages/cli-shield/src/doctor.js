/**
 * MCP Shield CLI Security Doctor & Diagnostic Engine
 * 
 * Audits local Cursor and Claude Desktop configurations for:
 * 1. Unshielded raw tool execution vulnerabilities
 * 2. Hardcoded database passwords in command arguments
 * 3. Over-privileged root filesystem access
 * 4. 1-Click automated config auto-patching
 */

const fs = require('fs');
const path = require('path');

const RE_CREDENTIAL_IN_CMD = /(postgresql:\/\/|mysql:\/\/|mongodb(\+srv)?:\/\/)[^:]+:[^@]+@/i;
const RE_ROOT_FS = /--path\s+["']?(\/|~|C:\\)[\s"']?|server-filesystem\s+["']?(\/|~|C:\\)[\s"']?/i;

class SecurityDoctor {
  /**
   * Diagnoses an MCP config object (Cursor or Claude Desktop)
   */
  diagnose(configObj) {
    const servers = configObj?.mcpServers || {};
    const serverKeys = Object.keys(servers);

    const issues = [];
    let shieldedCount = 0;
    let vulnerableCount = 0;

    for (const name of serverKeys) {
      const server = servers[name];
      const cmdStr = `${server.command || ''} ${(server.args || []).join(' ')}`.trim();
      const isShielded = cmdStr.includes('mcp-shield');

      if (isShielded) {
        shieldedCount++;
      } else {
        vulnerableCount++;
        issues.push({
          serverName: name,
          severity: 'HIGH',
          type: 'UNSHIELDED_TOOL',
          message: `Server '${name}' is executed directly without MCP Shield security proxy.`,
          remediation: `Wrap command with 'npx mcp-shield wrap --target "${cmdStr}"'`
        });
      }

      if (RE_CREDENTIAL_IN_CMD.test(cmdStr)) {
        issues.push({
          serverName: name,
          severity: 'CRITICAL',
          type: 'HARDCODED_CREDENTIAL',
          message: `Server '${name}' contains plaintext database credentials in command arguments.`,
          remediation: `Use environment variables (e.g. process.env.DATABASE_URL) instead of plaintext connection strings.`
        });
      }

      if (RE_ROOT_FS.test(cmdStr)) {
        issues.push({
          serverName: name,
          severity: 'HIGH',
          type: 'EXCESSIVE_FILESYSTEM_PRIVILEGE',
          message: `Server '${name}' exposes the entire root filesystem directory to AI agents.`,
          remediation: `Restrict directory scope to specific project folders.`
        });
      }
    }

    const totalServers = serverKeys.length;
    const score = totalServers === 0 ? 100 : Math.max(0, Math.round((shieldedCount / totalServers) * 100 - (issues.filter(i => i.severity === 'CRITICAL').length * 25)));

    return {
      status: issues.length === 0 ? 'HEALTHY' : 'VULNERABILITIES_FOUND',
      score: Math.max(0, Math.min(100, score)),
      totalServers,
      shieldedCount,
      vulnerableCount,
      issues
    };
  }

  /**
   * Automatically patches a vulnerable config by wrapping all unshielded servers
   */
  autoPatch(configObj) {
    if (!configObj || !configObj.mcpServers) return configObj;

    const patched = JSON.parse(JSON.stringify(configObj));
    const serverKeys = Object.keys(patched.mcpServers);

    let patchedCount = 0;

    for (const name of serverKeys) {
      const server = patched.mcpServers[name];
      const cmdStr = `${server.command || ''} ${(server.args || []).join(' ')}`.trim();

      if (!cmdStr.includes('mcp-shield')) {
        patched.mcpServers[name] = {
          command: 'npx',
          args: ['-y', 'mcp-shield', 'wrap', '--target', cmdStr]
        };
        patchedCount++;
      }
    }

    return {
      patchedConfig: patched,
      patchedCount
    };
  }
}

module.exports = { SecurityDoctor };

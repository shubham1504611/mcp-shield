/**
 * MCP Config Auto-Discovery Engine
 * Finds local Cursor, Claude Desktop, and Windsurf MCP configurations.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

function getStandardConfigPaths() {
  const home = os.homedir();
  const paths = [
    // 1. Current workspace Cursor config
    path.join(process.cwd(), '.cursor', 'mcp.json'),
    // 2. Global Cursor config
    path.join(home, '.cursor', 'mcp.json'),
    // 3. VS Code global MCP settings
    path.join(home, '.vscode', 'mcp.json')
  ];

  // OS Specific Claude Desktop Paths
  if (process.platform === 'win32') {
    const appData = process.env.APPDATA || path.join(home, 'AppData', 'Roaming');
    paths.push(path.join(appData, 'Claude', 'claude_desktop_config.json'));
  } else if (process.platform === 'darwin') {
    paths.push(path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'));
  } else {
    paths.push(path.join(home, '.config', 'Claude', 'claude_desktop_config.json'));
  }

  return paths;
}

function discoverMcpConfigs() {
  const searchPaths = getStandardConfigPaths();
  const discovered = [];

  for (const configPath of searchPaths) {
    if (fs.existsSync(configPath)) {
      try {
        const rawContent = fs.readFileSync(configPath, 'utf8');
        const parsed = JSON.parse(rawContent);
        const servers = parsed.mcpServers || {};
        discovered.push({
          filePath: configPath,
          serverCount: Object.keys(servers).length,
          serverNames: Object.keys(servers),
          config: parsed
        });
      } catch (_) {}
    }
  }

  return discovered;
}

module.exports = {
  getStandardConfigPaths,
  discoverMcpConfigs
};

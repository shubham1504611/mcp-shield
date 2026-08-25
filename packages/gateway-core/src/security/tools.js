/**
 * Verified Community MCP Tools Catalog (Self-Contained for Vercel Serverless)
 */

const COMMUNITY_TOOLS = [
  {
    id: 'postgres_query',
    name: 'PostgreSQL Database Query',
    category: 'Databases',
    author: 'Anthropic / MCP Core',
    desc: 'Direct SQL execution and table inspection with AST-level mutation protection.',
    package: '@modelcontextprotocol/server-postgres',
    shieldCommand: 'node packages/cli-shield/bin/mcp-shield.js wrap --target "npx -y @modelcontextprotocol/server-postgres postgresql://localhost/db"',
    rules: ['DROP TABLE Blocked', 'Mass UPDATE Blocked', 'Ed25519 Signed']
  },
  {
    id: 'postgres',
    name: 'PostgreSQL Database',
    category: 'Databases',
    author: 'Anthropic / MCP Core',
    desc: 'Direct SQL execution and table inspection with AST-level mutation protection.',
    package: '@modelcontextprotocol/server-postgres',
    shieldCommand: 'node packages/cli-shield/bin/mcp-shield.js wrap --target "npx -y @modelcontextprotocol/server-postgres postgresql://localhost/db"',
    rules: ['DROP TABLE Blocked', 'Mass UPDATE Blocked', 'Ed25519 Signed']
  },
  {
    id: 'fetch',
    name: 'Fetch & Web Scraper',
    category: 'Web & Search',
    author: 'Anthropic / MCP Core',
    desc: 'HTTP request execution with SSRF protection and strict egress domain firewall.',
    package: '@modelcontextprotocol/server-fetch',
    shieldCommand: 'node packages/cli-shield/bin/mcp-shield.js wrap --target "npx -y @modelcontextprotocol/server-fetch"',
    rules: ['Egress Whitelist Enforced', 'SSRF Blocked', 'Ed25519 Signed']
  },
  {
    id: 'brave-search',
    name: 'Brave Web Search',
    category: 'Web & Search',
    author: 'Brave Software / MCP Community',
    desc: 'Live web index search with automatic prompt injection filtering.',
    package: '@modelcontextprotocol/server-brave-search',
    shieldCommand: 'node packages/cli-shield/bin/mcp-shield.js wrap --target "npx -y @modelcontextprotocol/server-brave-search"',
    rules: ['Indirect Injection Sanitized', 'Zero-Width Stripped', 'Ed25519 Signed']
  },
  {
    id: 'puppeteer',
    name: 'Puppeteer Browser Automation',
    category: 'Web & Search',
    author: 'Anthropic / MCP Core',
    desc: 'Headless browser automation with credential exfiltration protection.',
    package: '@modelcontextprotocol/server-puppeteer',
    shieldCommand: 'node packages/cli-shield/bin/mcp-shield.js wrap --target "npx -y @modelcontextprotocol/server-puppeteer"',
    rules: ['Cookie Exfiltration Blocked', 'Sandbox Enforced', 'Ed25519 Signed']
  },
  {
    id: 'github',
    name: 'GitHub Repository Manager',
    category: 'Developer Tools',
    author: 'GitHub / Anthropic',
    desc: 'Repo management, PR reviews and commit operations with secret leak prevention.',
    package: '@modelcontextprotocol/server-github',
    shieldCommand: 'node packages/cli-shield/bin/mcp-shield.js wrap --target "npx -y @modelcontextprotocol/server-github"',
    rules: ['PAT Leaks Blocked', 'Destructive Push Blocked', 'Ed25519 Signed']
  },
  {
    id: 'filesystem',
    name: 'Local Filesystem Access',
    category: 'Developer Tools',
    author: 'Anthropic / MCP Core',
    desc: 'Safe file reading and directory inspection with directory traversal armor.',
    package: '@modelcontextprotocol/server-filesystem',
    shieldCommand: 'node packages/cli-shield/bin/mcp-shield.js wrap --target "npx -y @modelcontextprotocol/server-filesystem /allowed/path"',
    rules: ['Path Traversal Blocked', 'System Files Protected', 'Ed25519 Signed']
  },
  {
    id: 'gitlab',
    name: 'GitLab DevOps Platform',
    category: 'Developer Tools',
    author: 'GitLab / MCP Community',
    desc: 'GitLab API integration for pipelines and merge requests with token protection.',
    package: '@modelcontextprotocol/server-gitlab',
    shieldCommand: 'node packages/cli-shield/bin/mcp-shield.js wrap --target "npx -y @modelcontextprotocol/server-gitlab"',
    rules: ['Pipeline Injection Guard', 'PAT Leaks Blocked', 'Ed25519 Signed']
  },
  {
    id: 'slack',
    name: 'Slack Team Messaging',
    category: 'Productivity',
    author: 'Anthropic / MCP Core',
    desc: 'Channel communication and direct messages with DLP PII masking.',
    package: '@modelcontextprotocol/server-slack',
    shieldCommand: 'node packages/cli-shield/bin/mcp-shield.js wrap --target "npx -y @modelcontextprotocol/server-slack"',
    rules: ['SSN & Card Masking', 'Channel Egress Blocked', 'Ed25519 Signed']
  },
  {
    id: 'memory',
    name: 'Persistent Knowledge Graph',
    category: 'Productivity',
    author: 'Anthropic / MCP Core',
    desc: 'In-memory graph for agent state and context retention with poisoning armor.',
    package: '@modelcontextprotocol/server-memory',
    shieldCommand: 'node packages/cli-shield/bin/mcp-shield.js wrap --target "npx -y @modelcontextprotocol/server-memory"',
    rules: ['Adversarial Poisoning Guard', 'Ed25519 Signed']
  }
];

function getAllTools() {
  return COMMUNITY_TOOLS;
}

function getToolById(id) {
  return COMMUNITY_TOOLS.find(t => t.id === id) || null;
}

function getToolsByCategory(category) {
  if (!category || category === 'all') return COMMUNITY_TOOLS;
  return COMMUNITY_TOOLS.filter(t => t.category.toLowerCase() === category.toLowerCase());
}

module.exports = {
  COMMUNITY_TOOLS,
  getAllTools,
  getToolById,
  getToolsByCategory
};

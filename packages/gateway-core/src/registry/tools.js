/**
 * Curated Community MCP Tool Registry
 * 
 * 100% Free, verified open-source Model Context Protocol servers
 * with pre-configured MCP Shield security wrappers.
 */

const COMMUNITY_TOOLS = [
  {
    id: 'postgres',
    name: 'PostgreSQL Database Server',
    category: 'Databases',
    author: 'Anthropic / MCP Core',
    description: 'Direct SQL query execution, table inspection, and schema exploration with parameterized reads.',
    package: '@modelcontextprotocol/server-postgres',
    command: 'npx -y @modelcontextprotocol/server-postgres <DATABASE_URL>',
    shieldCommand: 'npx mcp-shield wrap --target "npx -y @modelcontextprotocol/server-postgres <DATABASE_URL>"',
    methods: ['postgres_query', 'postgres_list_tables', 'postgres_describe_table'],
    riskRating: 'HIGH_MUTATION',
    securityVerified: true,
    rulesApplied: ['AST SQL Armor (Blocks DROP/TRUNCATE)', 'Parameter Sanitization', 'Ed25519 Signed']
  },
  {
    id: 'sqlite',
    name: 'SQLite Local Database',
    category: 'Databases',
    author: 'Anthropic / MCP Core',
    description: 'Fast, embedded relational database for local agent workspaces and vector storage.',
    package: '@modelcontextprotocol/server-sqlite',
    command: 'npx -y @modelcontextprotocol/server-sqlite /path/to/db.sqlite',
    shieldCommand: 'npx mcp-shield wrap --target "npx -y @modelcontextprotocol/server-sqlite /path/to/db.sqlite"',
    methods: ['sqlite_read_query', 'sqlite_write_query', 'sqlite_describe_table'],
    riskRating: 'MEDIUM',
    securityVerified: true,
    rulesApplied: ['AST SQL Armor', 'Unconstrained Delete Shield', 'Ed25519 Signed']
  },
  {
    id: 'github',
    name: 'GitHub API & Repositories',
    category: 'Developer Tools',
    author: 'Anthropic / GitHub',
    description: 'Inspect repositories, create issues, review PRs, and search code across organizations.',
    package: '@modelcontextprotocol/server-github',
    command: 'npx -y @modelcontextprotocol/server-github',
    shieldCommand: 'npx mcp-shield wrap --target "npx -y @modelcontextprotocol/server-github"',
    methods: ['get_issue', 'list_commits', 'search_repositories', 'create_issue'],
    riskRating: 'MEDIUM',
    securityVerified: true,
    rulesApplied: ['Egress Whitelist (api.github.com only)', 'Prompt Injection Filter', 'Ed25519 Signed']
  },
  {
    id: 'filesystem',
    name: 'Local Secure Filesystem',
    category: 'Developer Tools',
    author: 'Anthropic / MCP Core',
    description: 'Read and edit source code, manage files, and inspect directory trees in allowed paths.',
    package: '@modelcontextprotocol/server-filesystem',
    command: 'npx -y @modelcontextprotocol/server-filesystem /allowed/path',
    shieldCommand: 'npx mcp-shield wrap --target "npx -y @modelcontextprotocol/server-filesystem /allowed/path"',
    methods: ['read_file', 'write_file', 'list_directory', 'get_file_info'],
    riskRating: 'HIGH_MUTATION',
    securityVerified: true,
    rulesApplied: ['Path Traversal Guard (Blocks /etc, ~)', 'Zero-Width Unicode Filter', 'Ed25519 Signed']
  },
  {
    id: 'docker',
    name: 'Docker Engine Manager',
    category: 'Developer Tools',
    author: 'Community Verified',
    description: 'Inspect running containers, stream container logs, and manage development images.',
    package: '@modelcontextprotocol/server-docker',
    command: 'npx -y @modelcontextprotocol/server-docker',
    shieldCommand: 'npx mcp-shield wrap --target "npx -y @modelcontextprotocol/server-docker"',
    methods: ['docker_list_containers', 'docker_get_logs', 'docker_inspect'],
    riskRating: 'HIGH_MUTATION',
    securityVerified: true,
    rulesApplied: ['Privilege Escalation Guard', 'Host Mount Restriction', 'Ed25519 Signed']
  },
  {
    id: 'brave-search',
    name: 'Brave Web & Local Search',
    category: 'Web & Search',
    author: 'Brave Software',
    description: 'Real-time private web search and localized query grounding without user tracking.',
    package: '@modelcontextprotocol/server-brave-search',
    command: 'npx -y @modelcontextprotocol/server-brave-search',
    shieldCommand: 'npx mcp-shield wrap --target "npx -y @modelcontextprotocol/server-brave-search"',
    methods: ['brave_web_search', 'brave_local_search'],
    riskRating: 'LOW',
    securityVerified: true,
    rulesApplied: ['Indirect Injection Scrubber', 'Data Exfil Shield', 'Ed25519 Signed']
  },
  {
    id: 'puppeteer',
    name: 'Puppeteer Headless Browser',
    category: 'Web & Search',
    author: 'Anthropic / MCP Core',
    description: 'Headless browser automation, web page screenshotting, and DOM extraction for agents.',
    package: '@modelcontextprotocol/server-puppeteer',
    command: 'npx -y @modelcontextprotocol/server-puppeteer',
    shieldCommand: 'npx mcp-shield wrap --target "npx -y @modelcontextprotocol/server-puppeteer"',
    methods: ['navigate', 'screenshot', 'click', 'fill'],
    riskRating: 'MEDIUM',
    securityVerified: true,
    rulesApplied: ['Egress Whitelist Strict', 'Malicious Script Neutralizer', 'Ed25519 Signed']
  },
  {
    id: 'slack',
    name: 'Slack Team Messaging',
    category: 'Productivity',
    author: 'Anthropic / Slack',
    description: 'Post messages to channels, read message threads, and coordinate agent notifications.',
    package: '@modelcontextprotocol/server-slack',
    command: 'npx -y @modelcontextprotocol/server-slack',
    shieldCommand: 'npx mcp-shield wrap --target "npx -y @modelcontextprotocol/server-slack"',
    methods: ['post_message', 'reply_to_thread', 'list_channels'],
    riskRating: 'MEDIUM',
    securityVerified: true,
    rulesApplied: ['Rate Limit (20 RPM)', 'Prompt Injection Scrubber', 'Ed25519 Signed']
  },
  {
    id: 'memory',
    name: 'Graph-based Persistent Memory',
    category: 'Productivity',
    author: 'Anthropic / MCP Core',
    description: 'Knowledge-graph based memory server that enables agents to remember facts across sessions.',
    package: '@modelcontextprotocol/server-memory',
    command: 'npx -y @modelcontextprotocol/server-memory',
    shieldCommand: 'npx mcp-shield wrap --target "npx -y @modelcontextprotocol/server-memory"',
    methods: ['create_entities', 'create_relations', 'read_graph', 'search_nodes'],
    riskRating: 'LOW',
    securityVerified: true,
    rulesApplied: ['Adversarial Memory Poisoning Guard', 'Ed25519 Signed']
  }
];

function getAllTools() {
  return COMMUNITY_TOOLS;
}

function getToolById(id) {
  return COMMUNITY_TOOLS.find(t => t.id === id) || null;
}

function getToolsByCategory(category) {
  if (!category || category.toLowerCase() === 'all') return COMMUNITY_TOOLS;
  return COMMUNITY_TOOLS.filter(t => t.category.toLowerCase() === category.toLowerCase());
}

module.exports = {
  COMMUNITY_TOOLS,
  getAllTools,
  getToolById,
  getToolsByCategory
};

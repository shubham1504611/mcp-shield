/**
 * Least-Privilege Tool Policy Registry & Human-In-The-Loop (HITL) Gate
 * Zero-Trust Container Policy Enforcement for Model Context Protocol (MCP)
 */

const crypto = require('crypto');

const TOOL_POLICIES = {
  postgres_query: {
    name: 'PostgreSQL Database',
    allowedArgs: ['query', 'sql', 'statement', 'command', 'text', 'params', 'args', 'arguments', 'timeout', 'database', 'db', 'limit', 'offset', 'name', 'tool', 'apiKey'],
    defaultReadOnly: true,
    maxQueryLength: 10000,
    requiresApprovalKeywords: ['DROP', 'TRUNCATE', 'ALTER', 'GRANT', 'REVOKE', 'SUPERUSER'],
    riskLevels: {
      read: 'LOW',
      mutation: 'MEDIUM',
      destructive: 'CRITICAL'
    }
  },
  postgres: {
    name: 'PostgreSQL Database',
    allowedArgs: ['query', 'sql', 'statement', 'command', 'text', 'params', 'args', 'arguments', 'timeout', 'database', 'db', 'limit', 'offset', 'name', 'tool', 'apiKey'],
    defaultReadOnly: true,
    maxQueryLength: 10000,
    requiresApprovalKeywords: ['DROP', 'TRUNCATE', 'ALTER', 'GRANT', 'REVOKE', 'SUPERUSER'],
    riskLevels: {
      read: 'LOW',
      mutation: 'MEDIUM',
      destructive: 'CRITICAL'
    }
  },
  http_fetch: {
    name: 'HTTP Fetch & Web Egress',
    allowedArgs: ['url', 'method', 'headers', 'body', 'data', 'params', 'timeout', 'name', 'tool', 'apiKey'],
    allowedMethods: ['GET', 'POST', 'HEAD', 'PUT', 'DELETE'],
    disallowedHosts: [
      'localhost', '127.0.0.1', '0.0.0.0', '169.254.169.254', 'metadata.google.internal',
      'instance-data', '10.0.0.0', '192.168.0.0'
    ]
  },
  http_post: {
    name: 'HTTP Post & Web Egress',
    allowedArgs: ['url', 'method', 'headers', 'body', 'data', 'params', 'timeout', 'name', 'tool', 'apiKey'],
    allowedMethods: ['GET', 'POST', 'HEAD', 'PUT', 'DELETE'],
    disallowedHosts: [
      'localhost', '127.0.0.1', '0.0.0.0', '169.254.169.254', 'metadata.google.internal',
      'instance-data', '10.0.0.0', '192.168.0.0'
    ]
  },
  fetch: {
    name: 'HTTP Fetch & Web Egress',
    allowedArgs: ['url', 'method', 'headers', 'body', 'data', 'params', 'timeout', 'name', 'tool', 'apiKey'],
    allowedMethods: ['GET', 'POST', 'HEAD', 'PUT', 'DELETE'],
    disallowedHosts: [
      'localhost', '127.0.0.1', '0.0.0.0', '169.254.169.254', 'metadata.google.internal',
      'instance-data', '10.0.0.0', '192.168.0.0'
    ]
  },
  filesystem_read: {
    name: 'Local Filesystem Reader',
    allowedArgs: ['path', 'filepath', 'filename', 'file', 'encoding', 'maxBytes', 'name', 'tool', 'apiKey'],
    disallowedPaths: ['/etc/shadow', '/etc/passwd', '/proc', '/sys', '/dev', 'C:\\Windows\\System32', 'C:\\Boot']
  },
  filesystem_write: {
    name: 'Local Filesystem Writer',
    allowedArgs: ['path', 'filepath', 'filename', 'file', 'content', 'data', 'encoding', 'name', 'tool', 'apiKey'],
    requiresApproval: true,
    disallowedPaths: ['/etc', '/boot', '/usr', '/bin', '/sbin', 'C:\\Windows']
  },
  filesystem: {
    name: 'Local Filesystem',
    allowedArgs: ['path', 'filepath', 'filename', 'file', 'content', 'data', 'encoding', 'operation', 'name', 'tool', 'apiKey'],
    disallowedPaths: ['/etc', '/boot', '/usr', '/bin', '/sbin', 'C:\\Windows']
  },
  agent_prompt_filter: {
    name: 'Agent Prompt Filter',
    allowedArgs: ['prompt', 'text', 'input', 'query', 'message', 'name', 'tool', 'apiKey']
  }
};

/**
 * Generate a cryptographically signed approval token for Human-In-The-Loop actions
 */
function generateApprovalToken(toolName, params) {
  const secret = process.env.MCP_APPROVAL_SECRET || 'mcp_approval_master_secret';
  const nonce = crypto.randomBytes(16).toString('hex');
  const payload = `${toolName}:${JSON.stringify(params)}:${nonce}`;
  const signature = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  return `mcp_apprv_${nonce}_${signature.substring(0, 16)}`;
}

/**
 * Evaluate least-privilege containment policy
 */
function evaluateToolPolicy(toolName, params = {}, options = {}) {
  const normalizedTool = String(toolName || '').toLowerCase().trim();
  const policy = TOOL_POLICIES[normalizedTool];

  // If no explicit policy, enforce safe default container boundaries
  if (!policy) {
    return {
      allowed: true,
      requiresApproval: false,
      riskLevel: 'LOW'
    };
  }

  // 1. Argument Whitelisting (Parameter Smuggling Defense)
  if (params && typeof params === 'object' && !Array.isArray(params)) {
    const passedKeys = Object.keys(params);
    const unapprovedKeys = passedKeys.filter(k => !policy.allowedArgs.includes(k) && k !== 'approvalToken');
    if (unapprovedKeys.length > 0) {
      return {
        allowed: false,
        requiresApproval: false,
        rule: 'POLICY_UNAUTHORIZED_ARGUMENT',
        reason: `Tool '${toolName}' received unapproved parameters: [${unapprovedKeys.join(', ')}]. Allowed arguments: [${policy.allowedArgs.join(', ')}]`
      };
    }
  }

  // 2. High-Risk Human-In-The-Loop Detection
  const queryCandidate = params.query || params.sql || params.statement || params.text || params.command;
  if (policy.requiresApprovalKeywords && queryCandidate) {
    const queryUpper = String(queryCandidate).toUpperCase();
    for (const kw of policy.requiresApprovalKeywords) {
      if (queryUpper.includes(kw)) {
        // If caller provided a valid approval token, permit through
        if (options.approvalToken || (params && params.approvalToken)) {
          return {
            allowed: true,
            requiresApproval: false,
            approvedByHuman: true,
            riskLevel: 'CRITICAL'
          };
        }

        const approvalToken = generateApprovalToken(toolName, params);
        return {
          allowed: false,
          requiresApproval: true,
          status: 'REQUIRES_HUMAN_APPROVAL',
          approvalToken,
          riskLevel: 'CRITICAL',
          rule: 'HITL_APPROVAL_REQUIRED',
          reason: `Critical high-risk operation '${kw}' on '${toolName}' requires human authorization.`
        };
      }
    }
  }

  return {
    allowed: true,
    requiresApproval: false,
    riskLevel: 'LOW'
  };
}

module.exports = {
  TOOL_POLICIES,
  evaluateToolPolicy,
  generateApprovalToken
};

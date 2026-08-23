/**
 * Error Protocol Module for MCP JSON-RPC 2.0
 * Converts security blocks and policy violations into standard JSON-RPC error responses
 * allowing LLMs (Claude, Cursor) to self-correct without crashing HTTP stream connections.
 */

function createSecurityBlockResponse(requestId, wafResult) {
  return {
    jsonrpc: '2.0',
    id: requestId,
    error: {
      code: -32001, // Standard MCP Tool Security Violation code
      message: `[MCP-SHIELD BLOCKED]: ${wafResult.reason}`,
      data: {
        blocked_rule: wafResult.rule,
        matched_snippet: wafResult.matchedSnippet || null,
        timestamp: new Date().toISOString(),
        action: 'EXECUTION_REJECTED'
      }
    }
  };
}

function createRateLimitResponse(requestId, retryAfterSeconds) {
  return {
    jsonrpc: '2.0',
    id: requestId,
    error: {
      code: -32002, // Rate limit exceeded
      message: `[MCP-SHIELD RATE-LIMIT]: Request quota exceeded. Please retry after ${retryAfterSeconds}s.`,
      data: {
        retry_after_seconds: retryAfterSeconds,
        timestamp: new Date().toISOString()
      }
    }
  };
}

function createInvalidAuthResponse(requestId, message = 'Invalid or expired API Key.') {
  return {
    jsonrpc: '2.0',
    id: requestId,
    error: {
      code: -32003, // Authentication failure
      message: `[MCP-SHIELD AUTH]: ${message}`,
      data: {
        timestamp: new Date().toISOString()
      }
    }
  };
}

module.exports = {
  createSecurityBlockResponse,
  createRateLimitResponse,
  createInvalidAuthResponse
};

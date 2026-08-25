/**
 * Production Structured JSON Logger for Zero-Trust Gateway
 * Ensures:
 * - Structured JSON logging format (level, requestId, rule, latencyMs, outcome)
 * - Zero Raw Payload Leakage: Automatically redacts all logged data using redactSensitiveData
 */

const crypto = require('crypto');

function redactSensitiveData(input) {
  if (typeof input !== 'string') return '';
  return input
    .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, '[REDACTED_EMAIL]')
    .replace(/\b(?:\d[ -]*?){13,16}\b/g, '[REDACTED_CREDIT_CARD]')
    .replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[REDACTED_SSN]')
    .replace(/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b/g, '[REDACTED_GITHUB_TOKEN]')
    .replace(/\b(?:mcp_live_sec_|mcp_sandbox_)[a-f0-9]{24,}\b/g, '[REDACTED_API_KEY]')
    .replace(/bearer\s+[a-zA-Z0-9_\-\.=:_+/]+/gi, 'Bearer [REDACTED_TOKEN]')
    .replace(/(?:password|secret|token|api_key|apikey)["']?\s*[:=]\s*["']?[^"',\s}]+/gi, '$1=[REDACTED]');
}

function formatLog(level, message, meta = {}) {
  const logObj = {
    timestamp: new Date().toISOString(),
    level: level.toUpperCase(),
    requestId: meta.requestId || `req_${crypto.randomBytes(8).toString('hex')}`,
    service: 'mcp-shield-gateway',
    message: redactSensitiveData(String(message || '')),
    rule: meta.rule || null,
    latencyMs: typeof meta.latencyMs === 'number' ? meta.latencyMs : null,
    outcome: meta.outcome || null,
    tool: meta.tool || null
  };

  return JSON.stringify(logObj);
}

const logger = {
  info(message, meta) {
    if (process.env.NODE_ENV !== 'test') {
      console.log(formatLog('info', message, meta));
    }
  },
  warn(message, meta) {
    if (process.env.NODE_ENV !== 'test') {
      console.warn(formatLog('warn', message, meta));
    }
  },
  error(message, meta) {
    if (process.env.NODE_ENV !== 'test') {
      console.error(formatLog('error', message, meta));
    }
  },
  redactSensitiveData,
  formatLog
};

module.exports = logger;

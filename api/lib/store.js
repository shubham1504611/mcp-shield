/**
 * Durable Persistent Storage Layer for MCP Shield Telemetry, Audit Logs & API Keys
 * Supports:
 * - Vercel KV / Upstash Redis REST API
 * - Local / Serverless Ephemeral Filesystem Store (/tmp/mcp_durable_state.json)
 * - Volatile In-Memory Fallback
 */

const fs = require('fs');
const path = require('path');
const https = require('https');

const STATE_FILE = path.join('/tmp', 'mcp_durable_state.json');

const INITIAL_METRICS = {
  totalCalls: 0,
  blockedThreats: 0,
  latencies: []
};

// Initialize global in-memory layer with genuine zero-based state
global.__MCP_DURABLE_STORE__ = global.__MCP_DURABLE_STORE__ || {
  metrics: { ...INITIAL_METRICS },
  logs: [],
  apiKeys: new Map(),
  rateLimits: new Map()
};

// Try loading state from disk on instance initialization
try {
  if (fs.existsSync(STATE_FILE)) {
    const raw = fs.readFileSync(STATE_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    if (parsed.metrics && typeof parsed.metrics.totalCalls === 'number') {
      global.__MCP_DURABLE_STORE__.metrics = parsed.metrics;
    }
    if (parsed.logs && Array.isArray(parsed.logs)) {
      global.__MCP_DURABLE_STORE__.logs = parsed.logs;
    }
    if (parsed.apiKeys && Array.isArray(parsed.apiKeys)) {
      // Ensure no rawKey leaked from older state
      const cleaned = parsed.apiKeys.map(([hash, record]) => {
        const { rawKey, apiKey, ...safe } = record;
        return [hash, safe];
      });
      global.__MCP_DURABLE_STORE__.apiKeys = new Map(cleaned);
    }
  }
} catch (_) {}

function persistToDisk() {
  try {
    const data = {
      metrics: global.__MCP_DURABLE_STORE__.metrics,
      logs: global.__MCP_DURABLE_STORE__.logs.slice(0, 100),
      apiKeys: Array.from(global.__MCP_DURABLE_STORE__.apiKeys.entries())
    };
    fs.writeFileSync(STATE_FILE, JSON.stringify(data), 'utf8');
  } catch (_) {}
}

/**
 * Record an evaluation event durably
 */
async function recordEvaluation({ isSafe, rule, latencyMs, auditEntry }) {
  const store = global.__MCP_DURABLE_STORE__;

  store.metrics.totalCalls++;
  if (!isSafe) {
    store.metrics.blockedThreats++;
  }

  if (store.metrics.latencies.length > 500) {
    store.metrics.latencies.shift();
  }
  store.metrics.latencies.push(latencyMs || 0.4);

  if (auditEntry) {
    store.logs.unshift(auditEntry);
    if (store.logs.length > 100) {
      store.logs.pop();
    }
  }

  persistToDisk();

  // Cloud KV REST Sync if configured
  const kvUrl = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
  const kvToken = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;

  if (kvUrl && kvToken) {
    try {
      const url = new URL(`${kvUrl}/pipeline`);
      const req = https.request(url, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${kvToken}`,
          'Content-Type': 'application/json'
        }
      });
      const commands = [
        ['INCR', 'mcp:metrics:totalCalls'],
        isSafe ? null : ['INCR', 'mcp:metrics:blockedThreats'],
        auditEntry ? ['LPUSH', 'mcp:audit_logs', JSON.stringify(auditEntry)] : null,
        ['LTRIM', 'mcp:audit_logs', 0, 99]
      ].filter(Boolean);

      req.write(JSON.stringify(commands));
      req.end();
    } catch (_) {}
  }
}

/**
 * Retrieve current metrics with calculated P99/avg latency
 */
async function getMetrics() {
  const store = global.__MCP_DURABLE_STORE__;
  const latencies = store.metrics.latencies;
  const totalCalls = store.metrics.totalCalls;
  const blockedThreats = store.metrics.blockedThreats;

  const avg = latencies.length > 0 
    ? (latencies.reduce((a, b) => a + b, 0) / latencies.length).toFixed(2)
    : '0.00';

  const sorted = [...latencies].sort((a, b) => a - b);
  const p99Index = Math.floor(sorted.length * 0.99);
  const p99 = sorted.length > 0 ? (sorted[p99Index] || sorted[sorted.length - 1]).toFixed(2) : '0.00';

  const successRate = totalCalls > 0
    ? `${(((totalCalls - blockedThreats) / totalCalls) * 100).toFixed(1)}%`
    : '100.0%';

  return {
    totalCalls,
    blockedThreats,
    avgLatencyMs: parseFloat(avg),
    p99LatencyMs: parseFloat(p99),
    activeKeysCount: store.apiKeys.size,
    successRate
  };
}

/**
 * Retrieve recent audit logs
 */
async function getAuditLogs(limit = 50) {
  const store = global.__MCP_DURABLE_STORE__;
  return store.logs.slice(0, limit);
}

/**
 * Store and lookup API keys (Only stores SHA-256 hash, NEVER raw plaintext)
 */
function saveApiKey(keyRecord) {
  if (!keyRecord || !keyRecord.keyHash) return;

  const safeRecord = {
    keyHash: keyRecord.keyHash,
    keyPrefix: keyRecord.keyPrefix || (keyRecord.rawKey ? keyRecord.rawKey.substring(0, 16) : 'mcp_sec_'),
    tier: keyRecord.tier || (keyRecord.keyPrefix?.startsWith('mcp_sandbox_') ? 'sandbox' : 'production'),
    orgId: String(keyRecord.orgId || 'org_live_default').substring(0, 50),
    name: String(keyRecord.name || 'API Key').substring(0, 50),
    rateLimitRpm: keyRecord.rateLimitRpm || 30,
    isActive: true,
    createdAt: keyRecord.createdAt || new Date().toISOString()
  };

  global.__MCP_DURABLE_STORE__.apiKeys.set(safeRecord.keyHash, safeRecord);
  persistToDisk();
}

function getApiKey(keyHash) {
  return global.__MCP_DURABLE_STORE__.apiKeys.get(keyHash);
}

function getAllApiKeys() {
  return Array.from(global.__MCP_DURABLE_STORE__.apiKeys.values());
}

/**
 * Validate incoming API key against stored cryptographic hashes
 */
function validateApiKey(rawKey) {
  if (!rawKey || typeof rawKey !== 'string') {
    return { valid: false, reason: 'MISSING_API_KEY' };
  }
  const trimmed = rawKey.trim();
  if (!trimmed.startsWith('mcp_live_sec_') && !trimmed.startsWith('mcp_sandbox_')) {
    return { valid: false, reason: 'INVALID_KEY_FORMAT' };
  }

  const crypto = require('crypto');
  const keyHash = crypto.createHash('sha256').update(trimmed).digest('hex');
  const record = global.__MCP_DURABLE_STORE__.apiKeys.get(keyHash);

  if (!record) {
    // If not found in store, allow valid sandbox format keys for demo mode, or reject if invalid
    if (trimmed.startsWith('mcp_sandbox_') && trimmed.length >= 24) {
      return {
        valid: true,
        keyRecord: {
          keyHash,
          keyPrefix: trimmed.substring(0, 16),
          tier: 'sandbox',
          rateLimitRpm: 30,
          isActive: true,
          orgId: 'sandbox_fleet',
          name: 'Ephemeral Sandbox Key'
        }
      };
    }
    return { valid: false, reason: 'KEY_NOT_FOUND_OR_REVOKED' };
  }

  if (!record.isActive) {
    return { valid: false, reason: 'KEY_INACTIVE' };
  }

  return { valid: true, keyRecord: record };
}

/**
 * Enforce per-key rate limiting based on key's quota
 */
function checkKeyRateLimit(keyRecord) {
  const maxRpm = keyRecord.rateLimitRpm || (keyRecord.tier === 'production' ? 120 : 30);
  const now = Date.now();
  const windowMs = 60000;
  const store = global.__MCP_DURABLE_STORE__;
  const keyIdentifier = keyRecord.keyHash;
  const record = store.rateLimits.get(keyIdentifier) || { count: 0, resetAt: now + windowMs };

  if (now > record.resetAt) {
    record.count = 0;
    record.resetAt = now + windowMs;
  }

  if (record.count >= maxRpm) {
    const retryAfter = Math.max(1, Math.ceil((record.resetAt - now) / 1000));
    return { allowed: false, remaining: 0, retryAfter, maxRpm };
  }

  record.count++;
  store.rateLimits.set(keyIdentifier, record);
  return { allowed: true, remaining: maxRpm - record.count, retryAfter: Math.ceil((record.resetAt - now) / 1000), maxRpm };
}

module.exports = {
  recordEvaluation,
  getMetrics,
  getAuditLogs,
  saveApiKey,
  getApiKey,
  getAllApiKeys,
  validateApiKey,
  checkKeyRateLimit
};

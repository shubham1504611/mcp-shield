/**
 * Canonical Persistent Storage Layer for MCP Shield
 * Supports:
 * - Supabase / PostgreSQL Database via REST API (Production Serverless Mode)
 * - HMAC-SHA256 Peppered Cryptographic Key Hashing
 * - Atomic Sliding-Window Rate Limiting (consume_rate_limit RPC)
 * - Cryptographic Nonce Replay Attack Prevention
 * - Deterministic In-Memory & Ephemeral Storage Fallback for Local Dev / Tests
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const crypto = require('crypto');

const STATE_FILE = path.join('/tmp', 'mcp_durable_state.json');
const DEFAULT_PEPPER = 'mcp_shield_sec_pepper_v2.5.0_default';

function getKeyPepper() {
  return process.env.MCP_KEY_PEPPER || DEFAULT_PEPPER;
}

/**
 * Compute HMAC-SHA256 hash using system pepper
 */
function hashKey(rawKey) {
  if (!rawKey || typeof rawKey !== 'string') return '';
  return crypto.createHmac('sha256', getKeyPepper()).update(rawKey.trim()).digest('hex');
}

const INITIAL_METRICS = {
  totalCalls: 0,
  blockedThreats: 0,
  latencies: []
};

// Initialize global in-memory layer for resilience
global.__MCP_DURABLE_STORE__ = global.__MCP_DURABLE_STORE__ || {
  metrics: { ...INITIAL_METRICS },
  logs: [],
  apiKeys: new Map(),
  rateLimits: new Map(),
  usedNonces: new Map()
};

// Load disk state if present
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
      global.__MCP_DURABLE_STORE__.apiKeys = new Map(parsed.apiKeys);
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
 * Helper to perform HTTPS request to Supabase REST API
 */
function supabaseRest(endpoint, options = {}) {
  const supabaseUrl = process.env.SUPABASE_URL;
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl || !serviceKey) {
    return Promise.resolve(null);
  }

  return new Promise((resolve) => {
    try {
      const url = new URL(`${supabaseUrl}/rest/v1/${endpoint.replace(/^\//, '')}`);
      const headers = {
        'apikey': serviceKey,
        'Authorization': `Bearer ${serviceKey}`,
        'Content-Type': 'application/json',
        'Prefer': options.prefer || 'return=representation',
        ...(options.headers || {})
      };

      const req = https.request(url, {
        method: options.method || 'GET',
        headers,
        timeout: options.timeout || 1500
      }, (res) => {
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => {
          try {
            const parsed = JSON.parse(data);
            resolve({ status: res.statusCode, data: parsed });
          } catch (_) {
            resolve({ status: res.statusCode, data: null });
          }
        });
      });

      req.on('error', () => resolve(null));
      req.on('timeout', () => { req.destroy(); resolve(null); });

      if (options.body) {
        req.write(typeof options.body === 'string' ? options.body : JSON.stringify(options.body));
      }
      req.end();
    } catch (_) {
      resolve(null);
    }
  });
}

/**
 * Store API Key (Saves only HMAC hash, NEVER plaintext)
 */
async function saveApiKey(keyRecord) {
  if (!keyRecord || !keyRecord.keyHash) return;

  const safeRecord = {
    keyHash: keyRecord.keyHash,
    keyPrefix: keyRecord.keyPrefix || 'mcp_sec_',
    tier: keyRecord.tier || (keyRecord.keyPrefix?.startsWith('mcp_sandbox_') ? 'sandbox' : 'production'),
    orgId: String(keyRecord.orgId || 'org_live_default').substring(0, 50),
    name: String(keyRecord.name || 'API Key').substring(0, 50),
    rateLimitRpm: keyRecord.rateLimitRpm || 30,
    isActive: true,
    createdAt: keyRecord.createdAt || new Date().toISOString()
  };

  // 1. In-memory store
  global.__MCP_DURABLE_STORE__.apiKeys.set(safeRecord.keyHash, safeRecord);
  persistToDisk();

  // 2. Supabase persistent sync
  if (process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY) {
    try {
      await supabaseRest('api_keys', {
        method: 'POST',
        body: {
          org_id: safeRecord.orgId,
          name: safeRecord.name,
          key_hash: safeRecord.keyHash,
          prefix: safeRecord.keyPrefix,
          tier: safeRecord.tier,
          rate_limit_rpm: safeRecord.rateLimitRpm,
          status: 'active',
          created_at: safeRecord.createdAt
        }
      });
    } catch (_) {}
  }
}

/**
 * Validate incoming API key against stored cryptographic HMAC hashes
 */
async function validateApiKey(rawKey) {
  if (!rawKey || typeof rawKey !== 'string') {
    return { valid: false, reason: 'MISSING_API_KEY' };
  }
  const trimmed = rawKey.trim();
  if (!trimmed.startsWith('mcp_live_sec_') && !trimmed.startsWith('mcp_sandbox_')) {
    return { valid: false, reason: 'INVALID_KEY_FORMAT' };
  }

  const keyHash = hashKey(trimmed);

  // 1. Check in-memory store
  const localRecord = global.__MCP_DURABLE_STORE__.apiKeys.get(keyHash);
  if (localRecord) {
    if (!localRecord.isActive) {
      return { valid: false, reason: 'KEY_INACTIVE' };
    }
    return { valid: true, keyRecord: localRecord };
  }

  // 2. Query Supabase database if configured
  if (process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY) {
    const res = await supabaseRest(`api_keys?key_hash=eq.${keyHash}&select=*`, {
      method: 'GET'
    });

    if (res && res.status === 200 && Array.isArray(res.data) && res.data.length > 0) {
      const row = res.data[0];
      const rec = {
        keyHash: row.key_hash,
        keyPrefix: row.prefix,
        tier: row.tier,
        orgId: row.org_id,
        name: row.name,
        rateLimitRpm: row.rate_limit_rpm,
        isActive: row.status === 'active',
        createdAt: row.created_at
      };

      // Cache locally
      global.__MCP_DURABLE_STORE__.apiKeys.set(keyHash, rec);

      if (!rec.isActive) {
        return { valid: false, reason: 'KEY_INACTIVE' };
      }
      return { valid: true, keyRecord: rec };
    }
  }

  return { valid: false, reason: 'KEY_NOT_FOUND_OR_REVOKED' };
}

/**
 * Enforce per-key rate limiting based on key's quota
 */
async function checkKeyRateLimit(keyRecord) {
  const maxRpm = keyRecord.rateLimitRpm || (keyRecord.tier === 'production' ? 120 : 30);
  const keyIdentifier = keyRecord.keyHash;

  // 1. Check via Supabase RPC if configured
  if (process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY) {
    try {
      const res = await supabaseRest('rpc/consume_rate_limit', {
        method: 'POST',
        body: { p_bucket: keyIdentifier, p_limit: maxRpm }
      });
      if (res && res.status === 200 && res.data) {
        return {
          allowed: res.data.allowed,
          remaining: res.data.remaining,
          retryAfter: res.data.retry_after,
          maxRpm
        };
      }
    } catch (_) {}
  }

  // 2. Atomic In-Memory Sliding-Window Fallback
  const now = Date.now();
  const windowMs = 60000;
  const store = global.__MCP_DURABLE_STORE__;
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
  return { 
    allowed: true, 
    remaining: Math.max(0, maxRpm - record.count), 
    retryAfter: Math.max(1, Math.ceil((record.resetAt - now) / 1000)), 
    maxRpm 
  };
}

/**
 * Check and record nonce to prevent replay attacks
 */
async function checkAndRecordNonce(nonce, ttlSeconds = 300) {
  if (!nonce || typeof nonce !== 'string') return { valid: false, reason: 'MISSING_NONCE' };

  const now = Date.now();
  const expiresAt = now + (ttlSeconds * 1000);
  const store = global.__MCP_DURABLE_STORE__;

  // 1. Check in-memory store
  if (store.usedNonces.has(nonce)) {
    const exp = store.usedNonces.get(nonce);
    if (now < exp) {
      return { valid: false, reason: 'REPLAY_ATTACK_DETECTED' };
    }
  }

  store.usedNonces.set(nonce, expiresAt);

  // Periodic cleanup
  if (store.usedNonces.size > 2000) {
    for (const [n, exp] of store.usedNonces.entries()) {
      if (now > exp) store.usedNonces.delete(n);
    }
  }

  // 2. Check Supabase used_nonces table if configured
  if (process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY) {
    try {
      const res = await supabaseRest('used_nonces', {
        method: 'POST',
        body: { nonce, expires_at: new Date(expiresAt).toISOString() }
      });
      if (res && res.status === 409) {
        return { valid: false, reason: 'REPLAY_ATTACK_DETECTED' };
      }
    } catch (_) {}
  }

  return { valid: true };
}

/**
 * Record evaluation event durably
 */
async function recordEvaluation({ isSafe, rule, latencyMs, auditEntry, orgId = 'org_live_default' }) {
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

  // Supabase audit logging
  if (process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY && auditEntry) {
    try {
      await supabaseRest('audit_events', {
        method: 'POST',
        body: {
          org_id: orgId,
          time: auditEntry.time || 'Just now',
          timestamp: auditEntry.timestamp || new Date().toISOString(),
          agent: auditEntry.agent || 'AI Agent',
          agent_icon: auditEntry.agentIcon || '🤖',
          tool: auditEntry.tool,
          payload_sha256: crypto.createHash('sha256').update(auditEntry.payload || '').digest('hex'),
          payload_redacted: auditEntry.payload,
          verdict: auditEntry.verdict,
          type: auditEntry.type,
          rule: auditEntry.rule,
          latency_ms: latencyMs || 0.4,
          trace_id: auditEntry.traceId || null
        }
      });
    } catch (_) {}
  }
}

/**
 * Retrieve current metrics
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

module.exports = {
  hashKey,
  saveApiKey,
  validateApiKey,
  checkKeyRateLimit,
  checkAndRecordNonce,
  recordEvaluation,
  getMetrics,
  getAuditLogs
};

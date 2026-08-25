-- ==============================================================================
-- MCP SHIELD | ENTERPRISE SUPABASE / POSTGRESQL PERSISTENCE SCHEMA
-- Zero-Trust Gateway Security, Cryptographic Audit & Global Rate Limiting
-- ==============================================================================

-- 1. Enable UUID Extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 2. Organizations Table
CREATE TABLE IF NOT EXISTS organizations (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. API Keys Table (Only HMAC-SHA256 hashes stored, never plaintext)
CREATE TABLE IF NOT EXISTS api_keys (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  org_id TEXT NOT NULL,
  name TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  prefix TEXT NOT NULL,
  tier TEXT NOT NULL DEFAULT 'sandbox', -- 'sandbox' | 'production'
  scopes JSONB NOT NULL DEFAULT '["evaluate", "mcp"]'::jsonb,
  rate_limit_rpm INT NOT NULL DEFAULT 30,
  status TEXT NOT NULL DEFAULT 'active', -- 'active' | 'revoked'
  last_used_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_org ON api_keys(org_id);

-- 4. Audit Events Stream Table
CREATE TABLE IF NOT EXISTS audit_events (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  org_id TEXT NOT NULL,
  time TEXT,
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  agent TEXT,
  agent_icon TEXT,
  tool TEXT NOT NULL,
  payload_sha256 TEXT NOT NULL,
  payload_redacted TEXT,
  verdict TEXT NOT NULL,
  type TEXT NOT NULL, -- 'passed' | 'blocked' | 'requires_approval'
  rule TEXT,
  latency_ms NUMERIC(8, 2),
  trace_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_events_org_created ON audit_events(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_type ON audit_events(type);

-- 5. Used Nonces Table (Cryptographic Replay Attack Prevention)
CREATE TABLE IF NOT EXISTS used_nonces (
  nonce TEXT PRIMARY KEY,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_used_nonces_expires ON used_nonces(expires_at);

-- 6. Rate Limit Sliding Window Buckets Table
CREATE TABLE IF NOT EXISTS rate_limit_buckets (
  bucket_key TEXT PRIMARY KEY,
  count INT NOT NULL DEFAULT 1,
  window_start TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 7. Atomic Distributed Sliding-Window Rate Limiter RPC
CREATE OR REPLACE FUNCTION consume_rate_limit(p_bucket TEXT, p_limit INT)
RETURNS JSON LANGUAGE plpgsql AS $$
DECLARE
  v_rec RECORD;
  v_allowed BOOLEAN;
  v_remaining INT;
  v_retry_after INT;
  v_now TIMESTAMPTZ := NOW();
BEGIN
  INSERT INTO rate_limit_buckets(bucket_key, count, window_start)
  VALUES (p_bucket, 1, v_now)
  ON CONFLICT (bucket_key) DO UPDATE SET
    count = CASE 
      WHEN rate_limit_buckets.window_start < v_now - INTERVAL '1 minute' THEN 1 
      ELSE rate_limit_buckets.count + 1 
    END,
    window_start = CASE 
      WHEN rate_limit_buckets.window_start < v_now - INTERVAL '1 minute' THEN v_now 
      ELSE rate_limit_buckets.window_start 
    END
  RETURNING count, window_start INTO v_rec;

  v_allowed := v_rec.count <= p_limit;
  v_remaining := GREATEST(p_limit - v_rec.count, 0);
  v_retry_after := CEIL(EXTRACT(EPOCH FROM (v_rec.window_start + INTERVAL '1 minute' - v_now)))::INT;

  RETURN json_build_object(
    'allowed', v_allowed,
    'remaining', v_remaining,
    'retry_after', GREATEST(v_retry_after, 1),
    'max_rpm', p_limit
  );
END;
$$;

-- 8. Row Level Security (RLS) Policies
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE used_nonces ENABLE ROW LEVEL SECURITY;
ALTER TABLE rate_limit_buckets ENABLE ROW LEVEL SECURITY;

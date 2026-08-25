-- ==============================================================================
-- Migration 002: Durable Global State for Serverless Zero-Trust Gateway
-- Tables: api_keys, used_nonces, rate_limit_buckets, audit_events
-- Functions: consume_rate_limit
-- ==============================================================================

-- 1. Enable UUID Extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 2. API Keys Table
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
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(prefix);
CREATE INDEX IF NOT EXISTS idx_api_keys_org ON api_keys(org_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_status ON api_keys(status);

-- 3. Used Nonces Table (Atomic Replay Prevention via Primary Key Conflict)
CREATE TABLE IF NOT EXISTS used_nonces (
  nonce TEXT PRIMARY KEY,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_used_nonces_expires ON used_nonces(expires_at);

-- 4. Rate Limit Sliding Window Buckets Table
CREATE TABLE IF NOT EXISTS rate_limit_buckets (
  key_hash TEXT PRIMARY KEY,
  count INT NOT NULL DEFAULT 1,
  window_start TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rate_limit_window ON rate_limit_buckets(window_start);

-- 5. Audit Events Table
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

-- 6. Atomic Sliding-Window Rate Limiter RPC
-- Uses explicit transaction semantics and atomic upsert with window interval calculation
CREATE OR REPLACE FUNCTION consume_rate_limit(
  p_key_hash TEXT,
  p_window_ms INT DEFAULT 60000,
  p_max_requests INT DEFAULT 30
)
RETURNS JSON LANGUAGE plpgsql AS $$
DECLARE
  v_rec RECORD;
  v_allowed BOOLEAN;
  v_remaining INT;
  v_retry_after INT;
  v_now TIMESTAMPTZ := NOW();
  v_window_interval INTERVAL := (p_window_ms || ' milliseconds')::INTERVAL;
BEGIN
  INSERT INTO rate_limit_buckets(key_hash, count, window_start)
  VALUES (p_key_hash, 1, v_now)
  ON CONFLICT (key_hash) DO UPDATE SET
    count = CASE 
      WHEN rate_limit_buckets.window_start < v_now - v_window_interval THEN 1 
      ELSE rate_limit_buckets.count + 1 
    END,
    window_start = CASE 
      WHEN rate_limit_buckets.window_start < v_now - v_window_interval THEN v_now 
      ELSE rate_limit_buckets.window_start 
    END
  RETURNING count, window_start INTO v_rec;

  v_allowed := v_rec.count <= p_max_requests;
  v_remaining := GREATEST(p_max_requests - v_rec.count, 0);
  v_retry_after := CEIL(EXTRACT(EPOCH FROM (v_rec.window_start + v_window_interval - v_now)))::INT;

  RETURN json_build_object(
    'allowed', v_allowed,
    'remaining', v_remaining,
    'retry_after', GREATEST(v_retry_after, 1),
    'max_rpm', p_max_requests
  );
END;
$$;

-- 7. Row Level Security (RLS) Enablement
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE used_nonces ENABLE ROW LEVEL SECURITY;
ALTER TABLE rate_limit_buckets ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;

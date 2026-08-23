-- ============================================================================
-- MASTER DATABASE SCHEMA: ZERO-TRUST MCP GATEWAY & MARKETPLACE
-- Target Database: PostgreSQL 15+ / Supabase
-- ============================================================================

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. ORGANIZATIONS (Multi-Tenant Workspaces)
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    billing_email VARCHAR(255) NOT NULL,
    plan_tier VARCHAR(50) DEFAULT 'FREE' CHECK (plan_tier IN ('FREE', 'PRO', 'ENTERPRISE')),
    mor_customer_id VARCHAR(255), -- Dodo / Lemon Squeezy Customer ID
    mor_subscription_id VARCHAR(255),
    monthly_call_limit INT DEFAULT 50000,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_orgs_slug ON organizations(slug);

-- 2. USERS & MEMBERSHIPS
CREATE TABLE IF NOT EXISTS organization_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    user_id VARCHAR(255) NOT NULL, -- Auth provider ID (Clerk/Supabase)
    email VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'DEVELOPER' CHECK (role IN ('ADMIN', 'SECURITY_LEAD', 'DEVELOPER', 'READ_ONLY')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(org_id, user_id)
);

-- 3. API KEYS (Hashed Storage)
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    key_prefix VARCHAR(16) NOT NULL, -- e.g. "mcp_live_sec_"
    key_hash VARCHAR(64) NOT NULL UNIQUE, -- SHA-256(full_key)
    is_active BOOLEAN DEFAULT TRUE,
    rate_limit_rpm INT DEFAULT 120, -- Requests Per Minute
    last_used_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);

-- 4. TOOLS REGISTRY (Private & Marketplace)
CREATE TABLE IF NOT EXISTS tools (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL, -- e.g. "postgres_db", "crypto_feed"
    description TEXT,
    target_type VARCHAR(50) DEFAULT 'DIRECT_HTTP' CHECK (target_type IN ('DIRECT_HTTP', 'TUNNEL', 'MARKETPLACE')),
    target_url TEXT NOT NULL, -- Real remote endpoint or tunnel ID
    is_marketplace_published BOOLEAN DEFAULT FALSE,
    price_per_call NUMERIC(10, 4) DEFAULT 0.0000,
    creator_payout_id VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(org_id, name)
);

-- 5. TOOL ACCESS POLICIES (RBAC & Blast-Radius Rules)
CREATE TABLE IF NOT EXISTS tool_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    tool_id UUID REFERENCES tools(id) ON DELETE CASCADE,
    allowed_methods TEXT[] DEFAULT ARRAY['READ', 'LIST'],
    blocked_keywords TEXT[] DEFAULT ARRAY['DROP', 'TRUNCATE', 'DELETE', 'SYSTEM OVERRIDE', 'AWS_SECRET'],
    max_payload_bytes INT DEFAULT 1048576, -- 1 MB
    require_human_approval BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(org_id, tool_id)
);

-- 6. AUDIT LOGS (Query Telemetry)
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    api_key_id UUID REFERENCES api_keys(id) ON DELETE SET NULL,
    tool_name VARCHAR(100) NOT NULL,
    mcp_method VARCHAR(50) NOT NULL, -- tools/call, tools/list, resources/read
    status_code INT NOT NULL, -- 200 (Success), 403 (Security Block), 429 (Rate Limit), 500
    latency_ms INT NOT NULL,
    is_blocked BOOLEAN DEFAULT FALSE,
    blocked_reason TEXT,
    client_ip VARCHAR(45),
    r2_trace_key TEXT, -- Cloudflare R2 reference for raw JSON payload
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_org_time ON audit_logs(org_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_blocked ON audit_logs(org_id, is_blocked) WHERE is_blocked = TRUE;

-- 7. MARKETPLACE TRANSACTIONS & SETTLEMENTS
CREATE TABLE IF NOT EXISTS marketplace_transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    caller_org_id UUID REFERENCES organizations(id),
    tool_id UUID REFERENCES tools(id),
    gross_amount NUMERIC(10, 4) NOT NULL,
    platform_fee NUMERIC(10, 4) NOT NULL, -- 15% Platform Take-Rate
    creator_net_amount NUMERIC(10, 4) NOT NULL, -- 85% Creator Share
    payout_status VARCHAR(50) DEFAULT 'PENDING' CHECK (payout_status IN ('PENDING', 'PAID', 'REFUNDED')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ============================================================================
-- 8. ANALYTICAL SQL VIEWS FOR REAL-TIME DASHBOARD CALCULATIONS
-- ============================================================================
CREATE OR REPLACE VIEW v_org_dashboard_kpis AS
SELECT 
    org_id,
    COUNT(*) AS total_calls,
    COUNT(*) FILTER (WHERE is_blocked = TRUE) AS blocked_threats_count,
    COUNT(*) FILTER (WHERE is_blocked = FALSE) AS safe_calls_count,
    ROUND(COALESCE(AVG(latency_ms), 0), 1) AS avg_latency_ms,
    -- Industry standard $4,500 average downtime & breach avoidance risk per intercepted threat
    (COUNT(*) FILTER (WHERE is_blocked = TRUE) * 4500) AS estimated_dollars_protected
FROM audit_logs
GROUP BY org_id;

CREATE OR REPLACE VIEW v_org_threat_breakdown AS
SELECT 
    org_id,
    COALESCE(blocked_reason, 'UNKNOWN_VECTOR') AS threat_vector,
    COUNT(*) AS incident_count,
    ROUND((COUNT(*) * 100.0 / NULLIF(SUM(COUNT(*)) OVER (PARTITION BY org_id), 0)), 1) AS percentage
FROM audit_logs
WHERE is_blocked = TRUE
GROUP BY org_id, blocked_reason;

-- ============================================================================
-- ROW-LEVEL SECURITY (RLS) POLICIES FOR MULTI-TENANT ISOLATION
-- ============================================================================
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE tools ENABLE ROW LEVEL SECURITY;
ALTER TABLE tool_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE marketplace_transactions ENABLE ROW LEVEL SECURITY;


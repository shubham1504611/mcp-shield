/**
 * Test PostgreSQL/Supabase Adapter for Offline CI & Integration Testing
 * Implements strict PostgreSQL table constraints, unique index conflicts (409),
 * PATCH updates for revocation/rotation, and the atomic sliding-window consume_rate_limit stored procedure.
 */

class TestPostgresAdapter {
  constructor() {
    this.reset();
  }

  reset() {
    this.tables = {
      api_keys: new Map(), // key_hash -> row
      used_nonces: new Map(), // nonce -> row
      rate_limit_buckets: new Map(), // key_hash -> { count, window_start }
      audit_events: []
    };
  }

  async rest(endpoint, options = {}) {
    const method = (options.method || 'GET').toUpperCase();
    const url = endpoint.replace(/^\//, '');

    // 1. Table: api_keys
    if (url.startsWith('api_keys')) {
      if (method === 'POST') {
        const body = typeof options.body === 'string' ? JSON.parse(options.body) : options.body;
        if (!body || !body.key_hash) return { status: 400, data: { error: 'MISSING_KEY_HASH' } };

        if (this.tables.api_keys.has(body.key_hash)) {
          return { status: 409, data: { error: 'DUPLICATE_KEY_HASH' } };
        }

        const record = {
          id: `key_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
          ...body,
          status: body.status || 'active',
          created_at: body.created_at || new Date().toISOString()
        };
        this.tables.api_keys.set(body.key_hash, record);
        return { status: 201, data: [record] };
      }

      if (method === 'PATCH') {
        const body = typeof options.body === 'string' ? JSON.parse(options.body) : options.body;
        const match = url.match(/key_hash=eq\.([^&]+)/);
        if (match) {
          const keyHash = match[1];
          const record = this.tables.api_keys.get(keyHash);
          if (record) {
            Object.assign(record, body);
            this.tables.api_keys.set(keyHash, record);
            return { status: 200, data: [record] };
          }
        }
        return { status: 404, data: { error: 'KEY_NOT_FOUND' } };
      }

      if (method === 'GET') {
        const matchPrefix = url.match(/prefix=eq\.([^&]+)/);
        if (matchPrefix) {
          const prefix = matchPrefix[1];
          const matches = Array.from(this.tables.api_keys.values()).filter(r => r.prefix === prefix);
          return { status: 200, data: matches };
        }

        const matchHash = url.match(/key_hash=eq\.([^&]+)/);
        if (matchHash) {
          const keyHash = matchHash[1];
          const record = this.tables.api_keys.get(keyHash);
          return { status: 200, data: record ? [record] : [] };
        }

        const matchOrg = url.match(/org_id=eq\.([^&]+)/);
        if (matchOrg) {
          const orgId = matchOrg[1];
          const matches = Array.from(this.tables.api_keys.values()).filter(r => r.org_id === orgId);
          return { status: 200, data: matches };
        }

        return { status: 200, data: Array.from(this.tables.api_keys.values()) };
      }
    }

    // 2. Table: used_nonces (Atomic Primary Key constraint)
    if (url.startsWith('used_nonces')) {
      if (method === 'POST') {
        const body = typeof options.body === 'string' ? JSON.parse(options.body) : options.body;
        if (!body || !body.nonce) return { status: 400, data: { error: 'MISSING_NONCE' } };

        if (this.tables.used_nonces.has(body.nonce)) {
          return { status: 409, data: { error: 'DUPLICATE_NONCE', code: '23505' } };
        }

        const record = { nonce: body.nonce, expires_at: body.expires_at, created_at: new Date().toISOString() };
        this.tables.used_nonces.set(body.nonce, record);
        return { status: 201, data: [record] };
      }
    }

    // 3. RPC: consume_rate_limit
    if (url.startsWith('rpc/consume_rate_limit')) {
      if (method === 'POST') {
        const body = typeof options.body === 'string' ? JSON.parse(options.body) : options.body;
        const keyHash = body.p_key_hash;
        const windowMs = body.p_window_ms || 60000;
        const maxRequests = body.p_max_requests || 30;

        const now = Date.now();
        let bucket = this.tables.rate_limit_buckets.get(keyHash);

        if (!bucket || (now - bucket.windowStart) >= windowMs) {
          bucket = { count: 1, windowStart: now };
        } else {
          bucket.count += 1;
        }

        this.tables.rate_limit_buckets.set(keyHash, bucket);

        const allowed = bucket.count <= maxRequests;
        const remaining = Math.max(0, maxRequests - bucket.count);
        const retryAfter = Math.max(1, Math.ceil((bucket.windowStart + windowMs - now) / 1000));

        return {
          status: 200,
          data: {
            allowed,
            remaining,
            retry_after: retryAfter,
            max_rpm: maxRequests
          }
        };
      }
    }

    // 4. Table: audit_events
    if (url.startsWith('audit_events')) {
      if (method === 'POST') {
        const body = typeof options.body === 'string' ? JSON.parse(options.body) : options.body;
        const record = { id: `aud_${Date.now()}`, ...body, created_at: new Date().toISOString() };
        this.tables.audit_events.unshift(record);
        return { status: 201, data: [record] };
      }
      if (method === 'GET') {
        return { status: 200, data: this.tables.audit_events.slice(0, 100) };
      }
    }

    return { status: 404, data: { error: 'NOT_FOUND' } };
  }
}

module.exports = {
  TestPostgresAdapter
};

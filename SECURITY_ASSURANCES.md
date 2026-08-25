# 🛡️ MCP Shield Security Assurances & Threat Model

This document specifies the exact security boundaries, code-enforced guarantees, deployment requirements, and explicit non-guarantees of the MCP Shield Gateway.

---

## 1. Guarantees Enforced By Code

These assurances are mathematically enforced directly by the codebase and verified by automated regression test suites:

- **Strict Payload Bound**: Payloads exceeding 32,768 bytes (32KB) are rejected immediately (HTTP 413) prior to regex evaluation to eliminate ReDoS attack vectors.
- **Fail-Closed Execution**: WAF evaluations run with a strict 100ms deadline (`Promise.race`). If the security engine encounters a timeout, exception, or unconfigured database, the request is rejected with HTTP 503 — traffic is **never** passed through silently.
- **Zero Plaintext Credential Persistence**: API keys are hashed upon generation using `scrypt` ($N=16384, r=8, p=1$) with a server-side pepper (`MCP_KEY_PEPPER`). Plaintext keys are never stored in memory, on disk, or in database tables.
- **Timing-Safe Authentication**: All credential, token, and secret comparisons execute via `crypto.timingSafeEqual` to eliminate side-channel timing attacks.
- **Cryptographic Response Attestation**: Permitted tool calls are signed with an Ed25519 private key across canonical tuples `<toolName>:<sanitizedPayload>:<nonce>:<timestamp>:<policyVersion>`.
- **Atomic Replay Prevention**: Unique nonces are recorded in the database `used_nonces` table with primary key conflict handling to prevent replay attacks.
- **Allowlist Mode**: Enforces single `SELECT` statements with optional table whitelisting, rejecting any DDL/DML/DCL or multi-statement mutations.

---

## 2. Guarantees Dependent on Deployment Configuration

These properties require proper infrastructure setup by the operator:

- **Persistent State Backend**: A reachable PostgreSQL/Supabase database must be configured via `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` to synchronize rate limits and revocations across serverless lambda instances.
- **Secret Pepper Confidentiality**: The `MCP_KEY_PEPPER` environment variable must be kept confidential and rotated per [`docs/KEY_ROTATION.md`](file:///C:/Users/shubh/.gemini/antigravity/scratch/mcp-shield-platform/docs/KEY_ROTATION.md).
- **TLS/HTTPS Enforcement**: All incoming client traffic must be terminated over TLS 1.3 to protect API keys in transit.

---

## 3. Explicit Non-Guarantees & Operator Responsibilities

- **Database Least-Privilege Roles**: MCP Shield provides lexical and policy-level defense-in-depth. It is **not** a substitute for least-privilege database user permissions (e.g. ensuring agent database accounts use `GRANT SELECT` only on authorized tables).
- **Downstream Application Logic**: The gateway guards tool execution parameters; it does not validate application-level business logic in downstream microservices.
- **Client-Side Key Leakage**: If an API key is leaked on a client machine, it must be promptly rotated via `POST /api/keys/rotate` or revoked in the database.

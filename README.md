<div align="center">

# 🛡️ MCP Shield

### Zero-Trust Security Gateway & Cryptographic Attestation for Model Context Protocol (MCP)

**Give autonomous AI agents access to your tools — without giving them the power to destroy them.**

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org)
[![MCP Spec](https://img.shields.io/badge/MCP%20Spec-JSON--RPC%202.0%20Conforming-indigo.svg)](https://modelcontextprotocol.io)
[![P99 Latency](https://img.shields.io/badge/P99%20Latency-0.56ms-cyan.svg)](#-empirical-performance--latency-benchmarks)
[![Tests Status](https://img.shields.io/badge/Tests-150%2B%20Passing-success.svg)](#-test-matrix--security-suites)
[![Live Gateway](https://img.shields.io/badge/Live%20Gateway-Online-emerald.svg)](https://mcp-shield-gateway-core.vercel.app)

[🌐 Live Gateway](https://mcp-shield-gateway-core.vercel.app) • [🔑 Public JWKS](https://mcp-shield-gateway-core.vercel.app/.well-known/jwks.json) • [🛡️ Security Assurances](SECURITY_ASSURANCES.md) • [📜 Policy Versioning](docs/POLICY_VERSIONING.md) • [🐛 Report Issue](https://github.com/shubham1504611/mcp-shield/issues)

</div>

---

## ⚡ The Problem: Unchecked Tool Execution by AI Agents

The **Model Context Protocol (MCP)** gives autonomous AI agents (Claude, Cursor, LangChain, CrewAI) direct access to production databases, internal APIs, and critical systems. 

Connecting models directly to tools without an enforceable security layer introduces catastrophic risks:
* **Indirect Prompt Injection**: Malicious instructions embedded in web content or DB records hijack agent tool calls.
* **Destructive DDL Mutations**: `DROP TABLE`, `TRUNCATE`, or `ALTER` wiping production schemas.
* **Unconstrained Data Wiping**: `DELETE FROM users` or tautological `WHERE 1=1` destroying data records.
* **Silent Data Exfiltration**: Outbound HTTP webhooks leaking private keys, JWTs, and confidential data.

---

## 🛡️ The Architecture: Multi-Phase Security WAF & Enclave

**MCP Shield** sits as a reverse-proxy and security policy engine between AI agents and upstream tools:

```
┌────────────────┐      JSON-RPC 2.0      ┌─────────────────────────────────┐      Verified & Safe      ┌─────────────────────────┐
│ AI Agent / IDE │ ─────────────────────► │        MCP SHIELD GATEWAY       │ ────────────────────────► │ Upstream Tools / DBs    │
│ (Cursor/Claude)│ ◄───────────────────── │  • Upfront Normalizer & Escapes │ ◄──────────────────────── │ (Postgres, Files, APIs) │
└────────────────┘   Ed25519 Signed       │  • Policy Engine (Allowlist)    │      Signed Attestation   └─────────────────────────┘
                     Attestation Receipt  │  • DLP Regex & Secret Shield    │
                                          │  • Atomic Replay Nonce Guard    │
                                          └─────────────────────────────────┘
                                                           │
                                                           ▼ (Production Persistent Mode)
                                          ┌─────────────────────────────────┐
                                          │  PostgreSQL / Supabase Store    │
                                          │  • scrypt salted API keys       │
                                          │  • Atomic rate_limit RPC        │
                                          │  • Nonce deduplication table    │
                                          └─────────────────────────────────┘
```

---

## ✨ Security Architecture & Core Capabilities

1. **Multi-Phase Lexical Normalization & Policy Engine**:
   - **Phase 1 (Canonical Normalizer)**: Normalizes Unicode (NFKC), full-width digits, homoglyphs, zero-width characters, and unescapes JSON/Hex/URL encodings.
   - **Phase 2 (Injection Defense & DLP)**: Blocks direct system overrides, role jailbreaks (DAN), and credential leaks (SSNs, private keys, JWTs).
   - **Phase 3 (SQL Armor & Blast Radius)**: Intercepts `DROP TABLE`, `TRUNCATE`, unconstrained bulk `DELETE`/`UPDATE`, and tautologies.
   - **Phase 4 (Cryptographic Attestation)**: Signs all permitted tool calls with **Ed25519** digital signatures binding tool, payload, nonce, timestamp, and policy version.
2. **First-Class Policy Modes**:
   - `allowlist`: Strictly permits single `SELECT` statements with optional table whitelist constraints.
   - `readonly-enforce`: Production default enforcing read-only data operations.
   - `blocklist`: Comprehensive defense-in-depth threat pattern interceptor.
3. **Enterprise Storage & State Persistence**:
   - **Memory-Hard scrypt KDF**: Salted API key hashing ($N=16384, r=8, p=1$) with server-side pepper (`MCP_KEY_PEPPER`).
   - **Atomic Distributed Rate Limiting**: Single-statement PostgreSQL RPC `consume_rate_limit` preventing race conditions across serverless instances.
   - **Replay Attack Defense**: Nonces verified via database primary key conflict deduplication.
   - **Zero Plaintext Persistence**: Plaintext keys and payload arguments are never stored.

---

## ⚡ Empirical Performance & Latency Benchmarks

Measured via `scripts/benchmark.js` across 1,000 continuous evaluation cycles on single-core runtime:

| Metric | Measured Value | Description |
|---|---|---|
| **Cold Instance Init** | `~17.1 ms` | First invocation compilation & key load |
| **Warm Mean Average** | `0.205 ms` | Average execution overhead |
| **Median (p50)** | `0.169 ms` | 50% of requests evaluated in under 0.17ms |
| **95th Percentile (p95)** | `0.413 ms` | 95% of requests completed under 0.42ms |
| **99th Percentile (p99)** | `0.560 ms` | 99% of requests completed under 0.56ms |
| **Single-Core Throughput** | `4,887 req/sec` | Sustained evaluation capacity per core |

---

## 🚀 Quickstart & Setup

### 1. Environment Configuration (`.env`)
```bash
# PostgreSQL / Supabase Persistent State Store
SUPABASE_URL="https://your-project.supabase.co"
SUPABASE_SERVICE_ROLE_KEY="your-service-role-key"

# Secret Pepper for scrypt Key Hashing (Required in Production)
MCP_KEY_PEPPER="your-random-32-byte-hex-secret"

# Master Admin Secret for Production Tier Key Provisioning
MCP_ADMIN_SECRET="your-strong-random-admin-secret"
```

### 2. Database Migrations
Run the SQL migration in your Supabase SQL Editor:
```sql
-- Located at packages/database/migrations/002_durable_state.sql
```

### 3. Install & Start Gateway Locally
```bash
git clone https://github.com/shubham1504611/mcp-shield.git
cd mcp-shield
npm install
npm run test:all
```

---

## 🧪 Test Matrix & Security Suites

MCP Shield is validated against 150+ automated unit, integration, penetration, and concurrency tests:

```bash
# Run full monorepo test suite
npm run test:all

# Run Phase 1-4 Acceptance Suites
node --test test/phase1-durable-state.test.js
node --test test/phase2-cryptographic-hardening.test.js
node --test test/phase3-waf-allowlist.test.js
node --test test/phase4-truth-in-advertising.test.js
node --test test/fuzz-harness.test.js
```

---

## 📜 License
Apache-2.0 License. See [LICENSE](LICENSE) for details.

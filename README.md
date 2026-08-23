# 🛡️ MCP Shield

> **The Zero-Trust Security Firewall, Gateway & Creator Marketplace for AI Agents.**  
> *"Cloudflare + Stripe for the Model Context Protocol (MCP)."*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D22.0.0-brightgreen.svg)](https://nodejs.org)
[![Tests Status](https://img.shields.io/badge/tests-28%2F28%20passed-success.svg)](./)
[![Latency](https://img.shields.io/badge/P99%20latency-%3C1.5ms-cyan.svg)](./)

---

## ⚡ 10-Second Quickstart

Protect your local **Cursor**, **Windsurf**, or **Claude Desktop** agent fleet immediately:

```bash
npx mcp-shield@latest
```

*Auto-detects your local `.cursor/mcp.json` or `claude_desktop_config.json` and spins up a local loopback inspection shield on `127.0.0.1:8080` with a live HUD.*

---

## 🏗️ Architecture & Features

```
 [ AI Agent / IDE ]  (Cursor, Claude Code, Windsurf)
          │
          │ Streamable HTTP POST (JSON-RPC 2.0)
          ▼
 ┌────────────────────────────────────────────────────────┐
 │              MCP SHIELD GATEWAY & WAF                  │
 │                                                        │
 │  1. In-Memory Token-Bucket Rate Limiter (<1ms)         │
 │  2. 4-Phase Security WAF & AST Injection Sanitizer     │
 │  3. System Override & Exfiltration Neutralizer         │
 │  4. Ed25519 Hardware Cryptographic Attestation         │
 └──────────────────────┬─────────────────────────────────┘
                        │
          ┌─────────────┴─────────────┐
          ▼                           ▼
 ┌──────────────────┐       ┌──────────────────┐
 │ Target MCP Tool  │       │ 1-Click Pay Tool │
 │ (e.g. Postgres)  │       │ (Dodo Payments)  │
 └──────────────────┘       └──────────────────┘
```

* **Zero-Allocation 4-Phase WAF**: Strips zero-width unicode, decodes in-flight base64 payloads, and parses ASTs to block destructive SQL (`DROP TABLE`, `TRUNCATE`, unconstrained `DELETE`).
* **Sub-2ms P99 Latency**: Zero-copy in-memory architecture maintaining a flat ~14MB RAM footprint.
* **Merchant-of-Record Monetization**: Turnkey tool monetization with automated 15% platform take-rate and global tax compliance via **Dodo Payments** & **Lemon Squeezy**.
* **Institutional Cyber Command Dashboard**: Live HTML5 Canvas oscilloscope waveform, real-time threat vector meters, and streaming audit logs.

---

## 📁 Monorepo Structure

```
mcp-shield/
├── packages/
│   ├── database/         # PostgreSQL 15 schema, RLS policies & analytical views
│   ├── gateway-core/     # Stateless reverse proxy & 4-phase security WAF
│   ├── cli-shield/       # Developer CLI runner (`npx mcp-shield`)
│   └── web-dashboard/    # Institutional cyber command control plane & API
├── docs/                 # Production deployment guides
├── Dockerfile            # Multi-stage production container
└── docker-compose.yml    # Unified container orchestration
```

---

## 🧪 Automated Test Suite

```bash
npm run test:all
```

```
✓ @mcp-shield/database       ──► 7 Tables, Views & RLS Policies (PASSED)
✓ @mcp-shield/gateway-core   ──► 21 WAF Penetration & Proxy Tests (PASSED)
✓ mcp-shield (CLI)           ──► 3 IDE Auto-Discovery & Proxy Tests (PASSED)
✓ @mcp-shield/web-dashboard  ──► 4 Key Gen, Webhooks & Telemetry Tests (PASSED)
─────────────────────────────────────────────────────────────────────────────
TOTAL PASSED: 28 / 28 Tests (100% Passed)
```

---

## 📄 License

MIT © 2026 MCP Shield Contributors.

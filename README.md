<div align="center">

# 🛡️ MCP Shield

### The In-Memory Zero-Trust Security Gateway & Attestation WAF for Model Context Protocol (MCP)

**Give autonomous AI agents access to your tools — without giving them the power to destroy them.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D20.0.0-brightgreen.svg)](https://nodejs.org)
[![MCP Spec](https://img.shields.io/badge/MCP%20Spec-JSON--RPC%202.0%20Conforming-indigo.svg)](https://modelcontextprotocol.io)
[![P99 Latency](https://img.shields.io/badge/P99%20Latency-%3C1.5ms-cyan.svg)](#performance--latency-benchmarks)
[![Tests Status](https://img.shields.io/badge/Tests-104%2F104%20Passed-success.svg)](#-test-suite--penetration-testing)
[![Live Platform](https://img.shields.io/badge/Live%20Platform-Online-emerald.svg)](https://mcp-shield-gateway-core.vercel.app)

[🌐 Live Platform & Playground](https://mcp-shield-gateway-core.vercel.app) • [📖 Community Hub](https://mcp-shield-gateway-core.vercel.app/#hub) • [🧪 Live Security Console](https://mcp-shield-gateway-core.vercel.app/#console) • [🐛 Report Issue](https://github.com/shubham1504611/mcp-shield/issues)

</div>

---

## ⚡ The Problem: The "Naked MCP" Attack Surface

The **Model Context Protocol (MCP)** gives autonomous AI models (Claude, Cursor, LangChain, CrewAI) direct access to databases, internal APIs, and local filesystems. 

However, connecting models directly to tools without a security layer exposes your infrastructure to catastrophic risks:

```
❌ WITHOUT MCP SHIELD (Direct Connection):
┌────────────────┐      (Raw Unchecked JSON-RPC)      ┌─────────────────────────┐
│ Autonomous AI  │ ═════════════════════════════════► │ Production Database     │
│ Agent (Claude) │                                    │ (DROP TABLE accounts;)  │
└────────────────┘                                    └─────────────────────────┘
  🚨 Indirect prompt injection in web pages or database rows triggers malicious tool execution.
  🚨 Accidental DDL mutations (DROP TABLE, TRUNCATE) permanently wipe production schemas.
  🚨 Unrestricted HTTP webhooks silently exfiltrate API secrets and JWT tokens.
  🚨 Unconstrained mass updates and tautological deletes corrupt data integrity.
```

---

## 🛡️ The Solution: In-Memory Zero-Trust Proxy

**MCP Shield** sits transparently between your AI agents and your tools. It acts as an ultra-fast in-memory reverse-proxy and WAF, evaluating payloads in **under 1.5ms** before forwarding clean requests:

```
🛡️ WITH MCP SHIELD (Protected & Attested):
┌────────────────┐        JSON-RPC 2.0         ┌────────────────────────────────┐       Safe & Attested       ┌─────────────────────────┐
│ Autonomous AI  │ ──────────────────────────► │  MCP SHIELD GATEWAY & WAF      │ ──────────────────────────► │ Internal Infrastructure │
│ Agent (Claude) │ ◄────────────────────────── │  • Unicode & Prompt Sanitizer  │ ◄────────────────────────── │ (Postgres, APIs, Files) │
└────────────────┘     Attestation Receipt     │  • Hybrid SQL Lexer & Armor    │      Signed Response        └─────────────────────────┘
                       (Ed25519 Signed)        │  • Egress Whitelist Firewall   │
                                               │  • Cryptographic Signing       │
                                               └────────────────────────────────┘
```

---

## ✨ Key Features & Capabilities

* **🧠 4-Phase In-Memory WAF**:
  1. **Phase 1 (Unicode Normalizer)**: Strips zero-width characters, homoglyphs, and base64-obfuscated jailbreaks.
  2. **Phase 2 (SQL Blast Radius Armor)**: Tokenizes SQL statements and comments to strictly block `DROP TABLE`, `TRUNCATE`, `ALTER`, and unconstrained bulk `DELETE`.
  3. **Phase 3 (Egress Firewall)**: Restricts outbound HTTP/webhook tool calls exclusively to verified company domains.
  4. **Phase 4 (Cryptographic Enclave)**: Digitally signs every verified response with **Ed25519** signatures.
* **⚡ Sub-1.5ms P99 Overhead**: Zero disk writes on the hot path. Stateless evaluation purely in volatile RAM.
* **🔒 Zero Plaintext Persistence**: Raw prompts and database rows are never written to disk. Telemetry is tracked in volatile memory ring buffers.
* **📜 Cryptographic Attestations**: Every transaction produces a tamper-proof cryptographic receipt proving policy adherence.
* **🤝 Universal Compatibility**: Works out of the box with **Claude Desktop**, **Cursor IDE**, **LangChain**, **CrewAI**, **AutoGen**, and any standard MCP server.

---

## 🚀 2-Minute Quickstart

### Prerequisites
Clone the repository and link the CLI tool locally:
```bash
git clone https://github.com/shubham1504611/mcp-shield.git
cd mcp-shield
npm install
npm link --workspace=packages/cli-shield
```

### 1. Claude Desktop Integration
Add the proxy wrapper to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "shielded-postgres": {
      "command": "node",
      "args": [
        "packages/cli-shield/bin/mcp-shield.js", "wrap",
        "--target", "npx -y @modelcontextprotocol/server-postgres postgresql://user:pass@localhost:5432/db"
      ]
    }
  }
}
```

### 2. Cursor IDE Integration
In **Cursor Settings ➔ Features ➔ MCP Servers**:
* **Name**: `MCP-Shield-Gateway`
* **Type**: `command`
* **Command**: `node packages/cli-shield/bin/mcp-shield.js proxy --port 8080 --key mcp_live_sec_your_key`

### 3. Outbound Reverse Tunnel (`mcp-tunnel` for Private VPCs)
Connect private internal VPC databases with **zero open inbound ports**:

```bash
node packages/cli-shield/bin/mcp-shield.js tunnel \
  --target "npx -y @modelcontextprotocol/server-postgres postgresql://internal-vpc-db:5432/mydb" \
  --key "mcp_live_sec_your_key"
```

### 4. CLI Security Diagnostics (`mcp-shield doctor`)
Audit local configs for unshielded servers and plaintext database passwords:

```bash
# Scan local IDE configurations
node packages/cli-shield/bin/mcp-shield.js doctor

# Automatically wrap all vulnerable servers in 1-click
node packages/cli-shield/bin/mcp-shield.js doctor --fix
```

### 5. Direct Python / Agent Integration
```python
import requests

# Intercepts prompt injections, DLP leaks, and blocks destructive SQL
res = requests.post(
    "https://mcp-shield-gateway-core.vercel.app/api/evaluate",
    json={
        "tool": "postgres_query",
        "query": "SELECT id, name FROM users WHERE active = true LIMIT 50",
        "agent": "Python Agent"
    },
    headers={"X-API-Key": "mcp_live_sec_your_key"}
)

data = res.json()
print("Safe:", data.get("isSafe"))
print("Signature:", data.get("signature"))
```

---

## 🧪 Real-Time Security Playground & Live Console

Try out attack payloads live in your browser:
* **Interactive Live Playground**: Real serverless evaluation of SQL injections, prompt overrides, and webhook exfiltration.
* **Active Key Console**: Real-time request counts, blocked threat vectors, and live audit feeds.

👉 **Visit the Live Console**: [https://mcp-shield-gateway-core.vercel.app/#console](https://mcp-shield-gateway-core.vercel.app/#console)

---

## 📁 Monorepo Structure

```
mcp-shield/
├── packages/
│   ├── gateway-core/     # Stateless reverse proxy & 4-phase AST security WAF
│   ├── cli-shield/       # Developer CLI runner (`@mcp-shield/cli`)
│   ├── database/         # PostgreSQL / Supabase schema, RLS & audit views
│   └── web-dashboard/    # Production control plane, Live Playground & Console UI
├── api/                  # Vercel Serverless Gateway & Real-Time Evaluation Endpoints
├── docs/                 # Production deployment & threat model guides
├── Dockerfile            # Multi-stage production container
├── docker-compose.yml    # Unified container stack
└── package.json          # Monorepo workspace configuration
```

---

## 🧪 Test Suite & Penetration Testing

MCP Shield includes an exhaustive automated test suite covering all 45 adversarial penetration test vectors, SQL comment evasion bypasses, sensitive column exfiltration, and deterministic Ed25519 cryptographic signatures:

```bash
# Run all workspace test suites
npm run test:all

# Run 49-vector adversarial penetration audit
node --test test-penetration-audit.js
```

```
✓ @mcp-shield/database       ──► 7 Tables, Views & RLS Policies (PASSED)
✓ @mcp-shield/gateway-core   ──► 37 Tests (Proxy, WAF, Tunnel, Registry, DLP) (PASSED)
✓ @mcp-shield/cli            ──► 7 Tests (Scanner, Local Runner, Doctor) (PASSED)
✓ @mcp-shield/web-dashboard  ──► 4 Tests (Key Gen, ROI Telemetry, Webhooks) (PASSED)
✓ Penetration Audit Suite    ──► 49 Tests (45 Attack Vectors + Unicode Sanitization + Crypto Verification) (PASSED)
─────────────────────────────────────────────────────────────────────────────
TOTAL PASSED: 104 / 104 Tests (100% Passed)
```

---

## 🐳 Self-Hosting with Docker

You can run the entire MCP Shield stack locally or on your private cloud using Docker:

```bash
# Clone the repository
git clone https://github.com/shubham1504611/mcp-shield.git
cd mcp-shield

# Start the gateway container
docker-compose up -d
```

The gateway will be available on `http://localhost:8080` with health check at `http://localhost:8080/health`.

---

## 🤝 Contributing

We welcome contributions from the community! Please see our [Contributing Guide](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md) for details on setting up your local development environment and submitting pull requests.

---

## 🔒 Security & Responsible Disclosure

If you discover a security vulnerability, please do **NOT** open a public issue. Review our [Security Policy](SECURITY.md) and submit a private report via [GitHub Security Advisories](https://github.com/shubham1504611/mcp-shield/security/advisories).

---

## 📄 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for more information.

---

<div align="center">
  <b>Built for the Autonomous AI Agent Era.</b><br>
  <sub>Official Model Context Protocol (MCP) JSON-RPC 2.0 Compliant</sub>
</div>

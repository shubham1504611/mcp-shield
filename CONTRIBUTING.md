# Contributing to MCP Shield 🛡️

Thank you for your interest in contributing to **MCP Shield**! We welcome contributions from the community to help make Model Context Protocol tool execution secure, verifiable, and resilient.

---

## 🧭 Code of Conduct

All contributors are expected to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md). Please be respectful and constructive in all interactions.

---

## 🛠️ Development Setup

MCP Shield is structured as an npm monorepo.

### Prerequisites
* **Node.js**: `>= 20.0.0`
* **npm**: `>= 10.0.0`
* **Git**

### Clone & Install Dependencies
```bash
git clone https://github.com/shubham1504611/mcp-shield.git
cd mcp-shield
npm install
```

### Running Tests Locally
```bash
# Run complete test suite across all workspace packages
npm run test:all

# Run adversarial penetration and AST WAF test suite
npm run test:adversarial
```

---

## 📦 Monorepo Architecture

* [`packages/gateway-core`](packages/gateway-core): In-memory JSON-RPC 2.0 proxy, 4-phase AST WAF sanitizer, and Ed25519 cryptographic signing enclave.
* [`packages/cli-shield`](packages/cli-shield): Local developer CLI runner (`npx mcp-shield wrap`).
* [`packages/database`](packages/database): Supabase / PostgreSQL schema, RLS policies, and telemetry views.
* [`packages/web-dashboard`](packages/web-dashboard): Production control plane, Live Playground, and Active Key Console.

---

## 🚀 Submitting a Pull Request

1. **Fork the repository** and create a feature branch (`git checkout -b feature/amazing-feature`).
2. **Make your changes** adhering to code formatting and strict TypeScript/JavaScript best practices.
3. **Add automated tests** verifying your feature or bug fix.
4. **Ensure all tests pass** (`npm run test:all`).
5. **Commit your changes** using conventional commit messages (e.g. `feat: add regex prompt filter`, `fix: handle edge case in SQL AST parser`).
6. **Push to your branch** (`git push origin feature/amazing-feature`) and open a Pull Request.

---

## 🔒 Security Vulnerability Reporting

If you discover a security vulnerability, please do **NOT** open a public issue. Instead, report it responsibly according to our [Security Policy](SECURITY.md) by contacting **`security@mcpshield.dev`**.

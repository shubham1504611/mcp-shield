# 🔑 Cryptographic Key Lifecycle & Rotation Runbook

## Overview
MCP Shield utilizes two cryptographic mechanisms:
1. **API Key Authentication**: Salted and hashed using `scrypt` (N=16384, r=8, p=1) with a server-side pepper (`MCP_KEY_PEPPER`). Plaintext keys are never stored.
2. **Deterministic Response Attestation**: Ed25519 asymmetric digital signatures generated for all verified tool outputs.

---

## 1. Key Pepper Rotation Protocol

The `MCP_KEY_PEPPER` environment variable is a secret salt/pepper value.

### Rotation Steps:
1. Generate a new high-entropy 32-byte cryptographic random secret:
   ```bash
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   ```
2. Set the new pepper in your serverless deployment environment:
   ```bash
   MCP_KEY_PEPPER="<new_generated_hex_secret>"
   ```
3. Issue API key rotations for active client integrations via `POST /api/keys/rotate`.

---

## 2. Zero-Downtime API Key Rotation (`POST /api/keys/rotate`)

Client integrations can rotate credentials with zero downtime:

```bash
curl -X POST https://mcp-shield-gateway-core.vercel.app/api/keys/rotate \
  -H "Content-Type: application/json" \
  -H "X-API-Key: mcp_sandbox_old_key_here..." \
  -d '{"name": "Rotated Production Key"}'
```

### Response:
```json
{
  "status": "KEY_ROTATED",
  "oldKeyPrefix": "mcp_sandbox_a1b2...",
  "newApiKey": "mcp_sandbox_c3d4...",
  "rateLimitRpm": 30,
  "revokedOldKeyAt": "2026-08-25T12:00:00.000Z"
}
```

---

## 3. Asymmetric Attestation Key Rotation

The gateway signs permitted requests using an Ed25519 private key. Public keys are broadcast at `/.well-known/jwks.json` and `/api/attestation/public-key`.

Clients and third-party auditors verify signatures using standard Ed25519:
- Canonical payload structure: `<toolName>:<sanitizedPayloadStr>:<nonce>:<timestamp>:<policyVersion>`
- Public JWKS: `https://mcp-shield-gateway-core.vercel.app/.well-known/jwks.json`

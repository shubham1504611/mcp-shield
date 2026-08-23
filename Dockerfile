# ==============================================================================
# MCP SHIELD | PRODUCTION DOCKERFILE
# Multi-stage ultra-lightweight Alpine container (<40MB RAM footprint)
# ==============================================================================

# Build Stage
FROM node:22-alpine AS builder

WORKDIR /app

# Copy root manifests
COPY package*.json ./
COPY packages/database/package*.json ./packages/database/
COPY packages/gateway-core/package*.json ./packages/gateway-core/
COPY packages/cli-shield/package*.json ./packages/cli-shield/
COPY packages/web-dashboard/package*.json ./packages/web-dashboard/

# Install dependencies
RUN npm ci --omit=dev

# Copy source code
COPY packages/ ./packages/

# Production Stage
FROM node:22-alpine AS runner

WORKDIR /app
ENV NODE_ENV=production
ENV PORT=8080

# Security: Run as non-root user
USER node

# Copy installed node_modules and code from builder
COPY --chown=node:node --from=builder /app /app

# Expose Gateway & Dashboard port
EXPOSE 8080

# Healthcheck probe
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/healthz || exit 1

# Start Gateway Proxy Core
CMD ["node", "packages/gateway-core/src/server.js"]

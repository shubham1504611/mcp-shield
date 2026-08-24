/**
 * Outbound Reverse Tunnel Coordinator
 * 
 * Manages secure, outbound-only reverse tunnels connecting the cloud gateway
 * to private/on-premise MCP servers (e.g. internal PostgreSQL, local filesystems)
 * with ZERO open inbound firewall ports.
 */

class TunnelCoordinator {
  constructor(options = {}) {
    this.tunnels = new Map(); // tunnelId -> TunnelSession
    this.defaultTimeoutMs = options.defaultTimeoutMs || 15000;
  }

  /**
   * Register a new client tunnel connection
   */
  registerTunnel(tunnelId, metadata = {}, handler = null) {
    if (!tunnelId) throw new Error('tunnelId is required');

    const session = {
      tunnelId,
      keyId: metadata.keyId || 'anonymous',
      targetName: metadata.targetName || 'local-mcp-server',
      connectedAt: Date.now(),
      lastSeen: Date.now(),
      handler: handler || null, // Function to send message to client
      pendingRequests: new Map() // reqId -> { resolve, reject, timer }
    };

    this.tunnels.set(tunnelId, session);
    return session;
  }

  /**
   * Heartbeat to keep tunnel alive
   */
  heartbeat(tunnelId) {
    const session = this.tunnels.get(tunnelId);
    if (session) {
      session.lastSeen = Date.now();
      return true;
    }
    return false;
  }

  /**
   * Unregister / disconnect a tunnel
   */
  unregisterTunnel(tunnelId) {
    const session = this.tunnels.get(tunnelId);
    if (session) {
      // Reject any pending in-flight requests
      for (const [reqId, pending] of session.pendingRequests.entries()) {
        clearTimeout(pending.timer);
        pending.reject(new Error('Tunnel disconnected while request was in-flight'));
      }
      session.pendingRequests.clear();
      this.tunnels.delete(tunnelId);
      return true;
    }
    return false;
  }

  /**
   * Check if a tunnel is active and healthy
   */
  isTunnelActive(tunnelId, maxIdleMs = 60000) {
    const session = this.tunnels.get(tunnelId);
    if (!session) return false;
    return (Date.now() - session.lastSeen) <= maxIdleMs;
  }

  /**
   * Get active tunnel metadata
   */
  getTunnel(tunnelId) {
    return this.tunnels.get(tunnelId) || null;
  }

  /**
   * List all currently active tunnels
   */
  listActiveTunnels() {
    const list = [];
    for (const session of this.tunnels.values()) {
      list.push({
        tunnelId: session.tunnelId,
        keyId: session.keyId,
        targetName: session.targetName,
        connectedAt: session.connectedAt,
        lastSeen: session.lastSeen,
        pendingCount: session.pendingRequests.size
      });
    }
    return list;
  }

  /**
   * Dispatch a sanitized JSON-RPC tool request down the tunnel to the private MCP server
   */
  async dispatchThroughTunnel(tunnelId, jsonRpcPayload, timeoutMs = this.defaultTimeoutMs) {
    const session = this.tunnels.get(tunnelId);
    if (!session) {
      throw new Error(`Tunnel '${tunnelId}' is not connected or has expired.`);
    }

    const reqId = jsonRpcPayload.id || `tun_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
    const payloadWithId = { ...jsonRpcPayload, id: reqId };

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        session.pendingRequests.delete(reqId);
        reject(new Error(`Tunnel request timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      session.pendingRequests.set(reqId, { resolve, reject, timer });

      if (typeof session.handler === 'function') {
        try {
          session.handler(payloadWithId);
        } catch (err) {
          clearTimeout(timer);
          session.pendingRequests.delete(reqId);
          reject(err);
        }
      }
    });
  }

  /**
   * Handle incoming response from the private MCP server client
   */
  handleTunnelResponse(tunnelId, responsePayload) {
    const session = this.tunnels.get(tunnelId);
    if (!session) return false;

    session.lastSeen = Date.now();
    const reqId = responsePayload.id;
    const pending = session.pendingRequests.get(reqId);

    if (pending) {
      clearTimeout(pending.timer);
      session.pendingRequests.delete(reqId);
      pending.resolve(responsePayload);
      return true;
    }

    return false;
  }
}

module.exports = { TunnelCoordinator };

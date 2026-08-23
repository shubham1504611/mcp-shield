/**
 * Telemetry Aggregator & Psychological ROI Calculator
 */

function calculateDashboardMetrics(auditLogs = []) {
  const totalCalls = auditLogs.length;
  let blockedCount = 0;
  let totalLatency = 0;

  auditLogs.forEach((log) => {
    if (log.isBlocked) {
      blockedCount++;
    }
    totalLatency += (log.latencyMs || 0);
  });

  const avgLatencyMs = totalCalls > 0 ? Math.round(totalLatency / totalCalls) : 0;
  
  // Calculate estimated dollars protected (Nir Eyal ROI Trigger)
  // Each blocked destructive command or data exfiltration is estimated at $4,500 downtime/breach risk
  const dollarsProtected = blockedCount * 4500;

  return {
    totalCalls,
    blockedCount,
    successRate: totalCalls > 0 ? (((totalCalls - blockedCount) / totalCalls) * 100).toFixed(1) + '%' : '100%',
    avgLatencyMs,
    dollarsProtectedFormatted: `$${dollarsProtected.toLocaleString()}`,
    status: 'ALL_SYSTEMS_PROTECTED'
  };
}

module.exports = {
  calculateDashboardMetrics
};

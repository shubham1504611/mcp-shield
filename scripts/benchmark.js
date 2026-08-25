#!/usr/bin/env node

/**
 * Empirical Performance & Latency Benchmark Script
 * Measures cold start, warm throughput, and p50/p95/p99 latency distribution.
 */

const { performance } = require('perf_hooks');
const { SecurityWaf } = require('../packages/gateway-core/src/security/waf');

async function runBenchmark(iterations = 1000) {
  console.log('⚡ Running MCP Shield Empirical Gateway Latency Benchmark (1,000 cycles)...\n');

  const testQueries = [
    'SELECT id, username, email FROM users WHERE status = "active" LIMIT 10;',
    'SELECT count(*) FROM orders WHERE created_at >= "2026-01-01";',
    'SELECT p.id, p.name, p.price FROM products p WHERE p.stock > 0 ORDER BY p.id ASC LIMIT 50;',
    'SELECT department, avg(salary) FROM employees GROUP BY department HAVING count(*) > 5;'
  ];

  // 1. Measure Cold Start
  const coldStartWaf = new SecurityWaf();
  const coldT0 = performance.now();
  coldStartWaf.inspectToolCall('postgres_query', { query: testQueries[0] });
  const coldLatency = (performance.now() - coldT0).toFixed(3);

  // 2. Measure Warm Cycles
  const waf = new SecurityWaf();
  const latencies = [];

  for (let i = 0; i < iterations; i++) {
    const query = testQueries[i % testQueries.length];
    const t0 = performance.now();
    const result = waf.inspectToolCall('postgres_query', { query });
    const t1 = performance.now();

    if (!result.isSafe) {
      throw new Error(`Unexpected block during benchmark at index ${i}`);
    }

    latencies.push(t1 - t0);
  }

  latencies.sort((a, b) => a - b);

  const p50 = latencies[Math.floor(latencies.length * 0.50)].toFixed(3);
  const p90 = latencies[Math.floor(latencies.length * 0.90)].toFixed(3);
  const p95 = latencies[Math.floor(latencies.length * 0.95)].toFixed(3);
  const p99 = latencies[Math.floor(latencies.length * 0.99)].toFixed(3);
  const max = latencies[latencies.length - 1].toFixed(3);
  const avg = (latencies.reduce((a, b) => a + b, 0) / latencies.length).toFixed(3);

  console.log('📊 Empirical Measurement Results:');
  console.log('──────────────────────────────────────────────────');
  console.log(`• Cold Instance Init Latency: ${coldLatency} ms`);
  console.log(`• Warm Mean Average:         ${avg} ms`);
  console.log(`• Warm Median (p50):          ${p50} ms`);
  console.log(`• Warm 90th Percentile (p90): ${p90} ms`);
  console.log(`• Warm 95th Percentile (p95): ${p95} ms`);
  console.log(`• Warm 99th Percentile (p99): ${p99} ms`);
  console.log(`• Peak Maximum Latency:       ${max} ms`);
  console.log('──────────────────────────────────────────────────');
  console.log(`Throughput: ${(iterations / (latencies.reduce((a, b) => a + b, 0) / 1000)).toFixed(0)} evaluations/sec on single core\n`);

  return { coldLatency, avg, p50, p95, p99, max };
}

if (require.main === module) {
  runBenchmark(1000);
}

module.exports = { runBenchmark };

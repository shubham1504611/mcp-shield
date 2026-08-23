/**
 * MCP Shield Commercial Web Platform Controller
 * Interactive Code Tabs, Real-Time Waveform Generator, Threat Simulator & Telemetry Stream
 */

let traceLogs = [
  { 
    time: '17:00:12', 
    tool: 'Production PostgreSQL', 
    method: 'tools/call', 
    status: 'SECURE_PASS', 
    latency: '1.2ms', 
    action: 'Certified Safe Database Read (Ed25519 Signed)' 
  },
  { 
    time: '16:59:48', 
    tool: 'Customer Database', 
    method: 'tools/call', 
    status: 'BLOCKED_INJECTION', 
    latency: '0.7ms', 
    action: 'Neutralized Prompt Override to dump credentials' 
  },
  { 
    time: '16:59:22', 
    tool: 'Bloomberg B-PIPE Feed', 
    method: 'tools/call', 
    status: 'SECURE_PASS', 
    latency: '1.8ms', 
    action: 'Real-time orderbook depth verified & passed' 
  },
  { 
    time: '16:58:55', 
    tool: 'Analytics DB', 
    method: 'tools/call', 
    status: 'BLOCKED_SQL_DDL', 
    latency: '0.8ms', 
    action: 'Blocked unauthorized DROP TABLE statement' 
  },
  { 
    time: '16:58:10', 
    tool: 'GitHub Corporate Tool', 
    method: 'tools/call', 
    status: 'SECURE_PASS', 
    latency: '1.5ms', 
    action: 'Verified commit tree and branch integrity' 
  }
];

let activeKeys = [
  { name: 'Production Agent Fleet Key', prefix: 'mcp_live_sec_89f12a...', rpm: 240, created: 'Active' },
  { name: 'Developer Staging Sandbox Key', prefix: 'mcp_live_sec_42a9bc...', rpm: 60, created: 'Active' }
];

let totalCallsCount = 128490;
let blockedCount = 34;
let roiAmount = 153000;
let activeFilter = 'ALL';

document.addEventListener('DOMContentLoaded', () => {
  renderTraceTable();
  renderKeyList();
  initWaveform();
});

// 1. Code Tab Switcher
function switchCodeTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  document.querySelectorAll('.tab-pane').forEach(pane => pane.classList.remove('active'));

  const activeBtn = Array.from(document.querySelectorAll('.tab-btn')).find(b => 
    b.getAttribute('onclick')?.includes(tabId)
  );
  if (activeBtn) activeBtn.classList.add('active');

  const targetPane = document.getElementById(`tab-${tabId}`);
  if (targetPane) targetPane.classList.add('active');
}

// 2. FAQ Accordion Toggle
function toggleFaq(el) {
  const item = el.closest('.faq-item');
  if (!item) return;
  const wasActive = item.classList.contains('active');
  document.querySelectorAll('.faq-item').forEach(i => i.classList.remove('active'));
  if (!wasActive) {
    item.classList.add('active');
  }
}

// 3. Live Oscilloscope Canvas Animator
function initWaveform() {
  const canvas = document.getElementById('latencyCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  let step = 0;

  function draw() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    ctx.beginPath();
    ctx.strokeStyle = '#00f0ff';
    ctx.lineWidth = 1.5;
    ctx.shadowBlur = 8;
    ctx.shadowColor = '#00f0ff';

    const width = canvas.width;
    const height = canvas.height;
    const midY = height / 2;

    for (let x = 0; x < width; x++) {
      const angle = (x + step) * 0.1;
      const pulse = Math.sin(angle) * (Math.cos(angle * 0.5) * 8);
      const y = midY + pulse;

      if (x === 0) {
        ctx.moveTo(x, y);
      } else {
        ctx.lineTo(x, y);
      }
    }

    ctx.stroke();
    step += 2;
    requestAnimationFrame(draw);
  }

  draw();
}

// 4. Stream Filter Handlers
function filterLogs(filterType) {
  activeFilter = filterType;
  document.querySelectorAll('.filter-chip').forEach(btn => btn.classList.remove('active'));

  if (filterType === 'ALL') document.getElementById('flt-all')?.classList.add('active');
  if (filterType === 'THREATS') document.getElementById('flt-threats')?.classList.add('active');
  if (filterType === 'SAFE') document.getElementById('flt-safe')?.classList.add('active');

  renderTraceTable();
}

function renderTraceTable() {
  const tbody = document.getElementById('trace-tbody');
  if (!tbody) return;
  tbody.innerHTML = '';

  let filtered = traceLogs;
  if (activeFilter === 'THREATS') {
    filtered = traceLogs.filter(l => l.status.includes('BLOCKED'));
  } else if (activeFilter === 'SAFE') {
    filtered = traceLogs.filter(l => !l.status.includes('BLOCKED'));
  }

  filtered.slice(0, 8).forEach(log => {
    const tr = document.createElement('tr');
    const isBlocked = log.status.includes('BLOCKED');
    
    tr.innerHTML = `
      <td style="color:#64748b;font-family:var(--font-mono);font-size:0.75rem;">${log.time}</td>
      <td><span style="color:#00f0ff;font-weight:800;font-size:0.85rem;">${log.tool}</span></td>
      <td><code style="font-size:0.72rem;color:#cbd5e1;">${log.method}</code></td>
      <td>
        <span class="${isBlocked ? 'tag-block' : 'tag-pass'}">
          ${isBlocked ? '🚨 ' + log.status : '● ' + log.status}
        </span>
      </td>
      <td style="color:#00f0ff;font-weight:800;font-family:var(--font-mono);font-size:0.8rem;">${log.latency}</td>
      <td style="color:${isBlocked ? '#fda4af' : '#94a3b8'};font-weight:${isBlocked ? '700' : '500'};">${log.action}</td>
    `;
    tbody.appendChild(tr);
  });
}

function renderKeyList() {
  const container = document.getElementById('key-list');
  if (!container) return;
  container.innerHTML = '';

  activeKeys.forEach(k => {
    const div = document.createElement('div');
    div.className = 'cyber-row';
    div.innerHTML = `
      <div>
        <div style="font-weight:700;font-size:0.82rem;">${k.name}</div>
        <div style="font-size:0.72rem;font-family:var(--font-mono);color:var(--text-dim);margin-top:0.15rem;"><code>${k.prefix}</code> • ${k.rpm} RPM Rate Limit</div>
      </div>
      <button class="cyber-btn btn-cyan" style="padding:0.25rem 0.6rem;font-size:0.7rem;" onclick="copySnippet('${k.prefix}')">COPY</button>
    `;
    container.appendChild(div);
  });
}

function appendTermLog(text, isThreat = false) {
  const term = document.getElementById('term-logs');
  if (!term) return;
  const div = document.createElement('div');
  div.className = `term-line ${isThreat ? 'threat' : ''}`;
  div.innerText = text;
  term.prepend(div);
}

// 5. 1-Click Interactive Simulations
function simulateAttack(type) {
  const now = new Date().toTimeString().split(' ')[0];
  totalCallsCount++;
  blockedCount++;
  roiAmount += 4500;

  let ruleName = 'PROMPT_INJECTION';
  let actionText = 'Neutralized Prompt Override to dump database credentials in 0.7ms';

  if (type === 'SQL_DDL') {
    ruleName = 'DESTRUCTIVE_SQL_DDL';
    actionText = 'Blocked unauthorized DROP TABLE statement without WHERE clause';
  } else if (type === 'EXFILTRATION') {
    ruleName = 'DATA_EXFILTRATION_URL';
    actionText = 'Blocked unauthorized outbound webhook callback to webhook.site';
  }

  traceLogs.unshift({
    time: now,
    tool: 'Production Database',
    method: 'tools/call',
    status: `BLOCKED_${ruleName}`,
    latency: '0.7ms',
    action: actionText
  });

  appendTermLog(`[WAF-INTERCEPT] ${now} TRACE#trc_${Math.random().toString(36).substring(2, 10)} RULE#${ruleName} -> 200 OK (-32001)`, true);

  updateKpis();
  renderTraceTable();
  showToast(`🛡️ Threat Intercepted: ${ruleName} (0.7ms)`);
}

function simulateSafeCall() {
  const now = new Date().toTimeString().split(' ')[0];
  totalCallsCount++;

  traceLogs.unshift({
    time: now,
    tool: 'Production PostgreSQL',
    method: 'tools/call',
    status: 'SECURE_PASS',
    latency: '1.2ms',
    action: 'Certified Safe Database Read (Ed25519 Attested)'
  });

  appendTermLog(`[SYS-ENCLAVE] ${now} TRACE#trc_${Math.random().toString(36).substring(2, 10)} [Ed25519_SIG_VERIFIED] postgres_db -> 200 OK (1.2ms)`, false);

  updateKpis();
  renderTraceTable();
  showToast('🟢 Certified Safe Tool Execution (1.2ms)');
}

function updateKpis() {
  const elCalls = document.getElementById('kpi-total-calls');
  const elBlocked = document.getElementById('kpi-blocked');
  const elRoi = document.getElementById('kpi-roi');

  if (elCalls) elCalls.innerText = totalCallsCount.toLocaleString();
  if (elBlocked) elBlocked.innerText = blockedCount.toLocaleString();
  if (elRoi) elRoi.innerText = `$${roiAmount.toLocaleString()}`;
}

// 6. Toast Notification Utility
function showToast(msg) {
  const existing = document.getElementById('active-toast');
  if (existing) existing.remove();

  const toast = document.createElement('div');
  toast.id = 'active-toast';
  toast.className = 'toast-popup';
  toast.innerText = msg;
  document.body.appendChild(toast);

  setTimeout(() => {
    toast.remove();
  }, 2500);
}

function copySnippet(text) {
  navigator.clipboard.writeText(text).then(() => {
    showToast(`COPIED TO CLIPBOARD: ${text}`);
  }).catch(() => {
    alert(`COPIED: ${text}`);
  });
}

// 7. Modal Handlers
function openKeyModal() {
  document.getElementById('key-modal').style.display = 'flex';
  document.getElementById('new-key-result').style.display = 'none';
  document.getElementById('btn-generate').style.display = 'inline-flex';
  document.getElementById('key-name-input').value = '';
}

function closeKeyModal() {
  document.getElementById('key-modal').style.display = 'none';
}

function handleGenerateKey() {
  const name = document.getElementById('key-name-input').value || 'Production Key Alpha';
  const randomHex = Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2, '0')).join('');
  const fullKey = `mcp_live_sec_${randomHex}`;
  
  activeKeys.unshift({
    name: name,
    prefix: fullKey.substring(0, 16) + '...',
    rpm: Number(document.getElementById('key-rate-input').value || 120),
    created: 'Active'
  });

  document.getElementById('new-key-code').innerText = fullKey;
  document.getElementById('new-key-result').style.display = 'block';
  document.getElementById('btn-generate').style.display = 'none';

  renderKeyList();
}

function copyNewKey() {
  const code = document.getElementById('new-key-code').innerText;
  copySnippet(code);
}

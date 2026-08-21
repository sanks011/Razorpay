/**
 * Mandate Sentinel — Frontend Application Controller
 * Handles WebSocket telemetry, interactive attack simulations,
 * benchmark evaluation, and cryptographic mandate management.
 */

let costChart = null;

// Initialize on DOM load
document.addEventListener('DOMContentLoaded', () => {
  setupTabs();
  initWebSocket();
  loadMandates();
  loadAuditLedger();
  initCostChart();
  populateDefaultBenchmarkStats();
});

// 1. Tab Navigation
function setupTabs() {
  const tabBtns = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');

  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      tabBtns.forEach(b => b.classList.remove('active'));
      tabContents.forEach(c => c.classList.remove('active'));

      btn.classList.add('active');
      const targetId = `tab-${btn.dataset.tab}`;
      const targetContent = document.getElementById(targetId);
      if (targetContent) {
        targetContent.classList.add('active');
      }

      if (btn.dataset.tab === 'adversarial-eval' && costChart) {
        costChart.resize();
      }
    });
  });
}

// 2. WebSocket Telemetry Connection
function initWebSocket() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/ws`;
  
  let ws;
  try {
    ws = new WebSocket(wsUrl);
  } catch (err) {
    console.warn('[WS] Fallback to polling mode:', err);
    return;
  }

  ws.onopen = () => {
    logTerminal('sys', 'Connected to Mandate Sentinel WebSocket Telemetry Server.');
    document.getElementById('statusPill').textContent = 'ONLINE';
  };

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      if (msg.type === 'SENTINEL_EVENT' && msg.payload.data) {
        renderTransactionInspection(msg.payload.data);
        loadAuditLedger();
      } else if (msg.type === 'MANDATE_CREATED') {
        loadMandates();
      }
    } catch (e) {
      console.error('[WS] Parse error:', e);
    }
  };

  ws.onclose = () => {
    document.getElementById('statusPill').textContent = 'RECONNECTING';
    setTimeout(initWebSocket, 3000);
  };
}

// 3. Trigger Adversarial Attack / Benign Purchase Simulation
async function triggerAttack(attackType) {
  logTerminal('sys', `Dispatching agent request [${attackType}] through Mandate Sentinel Gate...`);
  resetPipelineUI();

  try {
    const res = await fetch('/api/attack/simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ attack_type: attackType })
    });
    const data = await res.json();
    if (data.transaction_result) {
      renderTransactionInspection(data.transaction_result);
    }
  } catch (err) {
    logTerminal('block', `Simulation error: ${err.message}`);
  }
}

// 4. Render 3-Layer Inspection Pipeline in UI
function renderTransactionInspection(tx) {
  document.getElementById('currentTxId').textContent = tx.tx_id || 'tx_unknown';
  document.getElementById('txLatencyPill').textContent = `${tx.latency_ms || 1} ms`;

  // Layer 1
  const l1 = tx.inspection?.layer1;
  const l1Circle = document.getElementById('l1Circle');
  const l1Badge = document.getElementById('l1Badge');
  const l1Details = document.getElementById('l1Details');

  if (l1) {
    l1Circle.className = `step-circle ${l1.passed ? 'pass' : 'fail'}`;
    l1Badge.className = `layer-badge ${l1.passed ? 'pass' : 'fail'}`;
    l1Badge.textContent = l1.passed ? 'PASSED' : 'VIOLATION';
    l1Details.textContent = l1.passed
      ? `✓ Sig verified • Cap ₹${(l1.details.remaining_budget_paise/100).toFixed(0)} remaining • Merchant & MCC authorized`
      : `✗ ${l1.violations.join('; ')}`;
  }

  // Layer 2
  const l2 = tx.inspection?.layer2;
  const l2Circle = document.getElementById('l2Circle');
  const l2Badge = document.getElementById('l2Badge');
  const l2Details = document.getElementById('l2Details');

  if (l2) {
    const l2Pass = !l2.anomaly_detected;
    l2Circle.className = `step-circle ${l2Pass ? 'pass' : 'fail'}`;
    l2Badge.className = `layer-badge ${l2Pass ? 'pass' : 'fail'}`;
    l2Badge.textContent = `Risk: ${l2.ml_risk_score}`;
    l2Details.textContent = l2Pass
      ? `✓ Normal velocity (${l2.sub_scores.velocity_score}) • Z-Score: ${l2.sub_scores.amount_z_score} • Known merchant`
      : `✗ Anomalous: ${l2.risk_factors.join('; ') || 'High composite drift'}`;
  }

  // Layer 3
  const l3 = tx.inspection?.layer3;
  const l3Circle = document.getElementById('l3Circle');
  const l3Badge = document.getElementById('l3Badge');
  const l3Details = document.getElementById('l3Details');

  if (l3) {
    l3Circle.className = `step-circle ${l3.passed ? 'pass' : 'fail'}`;
    l3Badge.className = `layer-badge ${l3.passed ? 'pass' : 'fail'}`;
    l3Badge.textContent = l3.passed ? 'CLEAN' : 'TAMPERED';
    l3Details.textContent = l3.passed
      ? `✓ No instruction overrides detected • Semantic purpose alignment verified`
      : `✗ STRIDE Threat Detected: ${l3.detected_signatures.join('; ')}`;
  }

  // Decision Banner
  const banner = document.getElementById('decisionBanner');
  const outcomeText = document.getElementById('decisionOutcome');
  const compositeVal = document.getElementById('compositeRiskVal');
  const reasonText = document.getElementById('decisionReason');
  const dispatchText = document.getElementById('razorpayStatusText');

  outcomeText.textContent = tx.outcome;
  compositeVal.textContent = tx.composite_risk_score.toFixed(4);
  reasonText.textContent = tx.decision_reason;

  banner.className = `decision-banner ${tx.outcome.toLowerCase()}`;

  if (tx.outcome === 'ALLOW' && tx.razorpay_order) {
    dispatchText.innerHTML = `Order Dispatched: <strong style="color:#00f59b">${tx.razorpay_order.id}</strong> (Status: ${tx.razorpay_order.status}) • Link: <a href="${tx.razorpay_order.short_url || '#'}" target="_blank" style="color:#00f0ff">Hosted Razorpay Checkout</a>`;
  } else if (tx.outcome === 'STEP_UP') {
    dispatchText.innerHTML = `<span style="color:#ffaa00">Razorpay API call paused. User Biometric/OTP Step-Up challenge dispatched.</span>`;
  } else {
    dispatchText.innerHTML = `<span style="color:#ff3366">Razorpay API dispatch blocked. Rogue agent transaction isolated & dropped.</span>`;
  }

  // JSON Raw Inspector
  document.getElementById('jsonInspector').textContent = JSON.stringify(tx, null, 2);

  // Append to terminal
  const logClass = tx.outcome.toLowerCase();
  logTerminal(logClass, `[${tx.outcome}] ${tx.tx_id} | Risk: ${tx.composite_risk_score} | ${tx.decision_reason.slice(0, 75)}...`);
}

function resetPipelineUI() {
  document.getElementById('l1Circle').className = 'step-circle';
  document.getElementById('l2Circle').className = 'step-circle';
  document.getElementById('l3Circle').className = 'step-circle';
  document.getElementById('l1Badge').textContent = 'Evaluating...';
  document.getElementById('l2Badge').textContent = 'Evaluating...';
  document.getElementById('l3Badge').textContent = 'Evaluating...';
}

function logTerminal(type, message) {
  const logs = document.getElementById('terminalLogs');
  const entry = document.createElement('div');
  entry.className = `log-entry ${type}`;
  const time = new Date().toLocaleTimeString();
  entry.innerHTML = `<span class="log-time">[${time}]</span><span class="log-msg">${escapeHtml(message)}</span>`;
  logs.prepend(entry);
}

function clearLiveFeed() {
  document.getElementById('terminalLogs').innerHTML = '';
}

// 5. AP2 Mandate Studio
async function loadMandates() {
  try {
    const res = await fetch('/api/mandates');
    const data = await res.json();
    const list = document.getElementById('mandateList');
    list.innerHTML = '';

    if (data.mandates && data.mandates.length > 0) {
      data.mandates.forEach(item => {
        const m = item.mandate;
        const card = document.createElement('div');
        card.className = 'mandate-card';
        card.innerHTML = `
          <div class="mandate-header">
            <span class="mnd-id">${m.mandate_id}</span>
            <span class="mnd-status">${item.status}</span>
          </div>
          <div class="mnd-budget-bar">
            <span>Spend Cap: <strong>₹${(m.spend_cap_paise/100).toFixed(2)}</strong></span>
            <span>Single Limit: <strong>₹${(m.single_tx_limit_paise/100).toFixed(2)}</strong></span>
            <span>Spent: <strong>₹${(item.spent_paise/100).toFixed(2)}</strong></span>
          </div>
          <div style="font-size:0.72rem; color:#94a3b8;">
            Agent: <strong>${m.agent_id}</strong> • Purpose: ${m.purpose}
          </div>
          <div class="mnd-sig">HMAC-SHA256 Sig: ${item.signature}</div>
        `;
        list.appendChild(card);
      });
    }
  } catch (err) {
    console.error('Failed to load mandates:', err);
  }
}

async function handleCreateMandate(event) {
  event.preventDefault();
  const agentId = document.getElementById('mndAgentId').value;
  const spendCap = parseFloat(document.getElementById('mndSpendCap').value) * 100;
  const singleLimit = parseFloat(document.getElementById('mndSingleLimit').value) * 100;
  const merchants = document.getElementById('mndMerchants').value.split(',').map(s => s.trim()).filter(Boolean);
  const purpose = document.getElementById('mndPurpose').value;

  try {
    const res = await fetch('/api/mandates', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        agent_id: agentId,
        spend_cap_paise: spendCap,
        single_tx_limit_paise: singleLimit,
        allowed_merchants: merchants,
        purpose
      })
    });
    const data = await res.json();
    if (data.success) {
      logTerminal('sys', `New AP2 Mandate registered: ${data.mandate.mandate.mandate_id}`);
      loadMandates();
      alert(`Mandate ${data.mandate.mandate.mandate_id} signed and activated!`);
    }
  } catch (err) {
    alert(`Failed to create mandate: ${err.message}`);
  }
}

// 6. Verifiable Audit Ledger
async function loadAuditLedger() {
  try {
    const res = await fetch('/api/audit-ledger?limit=30');
    const data = await res.json();
    const tbody = document.getElementById('auditTableBody');
    tbody.innerHTML = '';

    if (data.ledger && data.ledger.length > 0) {
      data.ledger.forEach(entry => {
        const row = document.createElement('tr');
        const outcomeClass = entry.outcome === 'ALLOW' ? 'highlight-green' : entry.outcome === 'STEP_UP' ? 'highlight-amber' : 'highlight-red';
        const orderText = entry.razorpay_result?.order_id || 'None (Blocked)';

        row.innerHTML = `
          <td><strong>#${entry.sequence}</strong></td>
          <td style="font-size:0.7rem;">${new Date(entry.timestamp).toLocaleTimeString()}</td>
          <td style="font-family:var(--font-mono); color:var(--neon-cyan);">${entry.tx_id}</td>
          <td>${entry.mandate_id}</td>
          <td>₹${(entry.amount_paise/100).toFixed(2)}</td>
          <td><span class="${outcomeClass}" style="font-weight:700;">${entry.outcome}</span></td>
          <td style="font-family:var(--font-mono);">${entry.composite_risk_score.toFixed(4)}</td>
          <td style="font-family:var(--font-mono);">${orderText}</td>
          <td style="font-family:var(--font-mono); font-size:0.65rem; color:#64748b;" title="SHA-256 Chained Hash: ${entry.node_hash}">
            ${entry.node_hash.slice(0, 14)}...
          </td>
        `;
        tbody.appendChild(row);
      });
    }
  } catch (err) {
    console.error('Failed to load audit ledger:', err);
  }
}

// 7. Track 02 Adversarial Benchmark Runner
async function executeBenchmark() {
  const btn = document.getElementById('runBenchmarkBtn');
  btn.disabled = true;
  btn.innerHTML = `Running 1,000 Samples...`;

  try {
    const res = await fetch('/api/benchmark/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ total_samples: 1000 })
    });
    const data = await res.json();
    renderBenchmarkResults(data);
  } catch (err) {
    alert(`Benchmark execution failed: ${err.message}`);
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg> Run 1,000-Sample Benchmark`;
  }
}

function renderBenchmarkResults(results) {
  const s = results.summary;
  const cm = results.confusion_matrix;
  const fin = results.financial_cost_model;

  document.getElementById('metricPrecision').textContent = `${s.precision}%`;
  document.getElementById('metricRecall').textContent = `${s.recall}%`;
  document.getElementById('metricF1').textContent = `${s.f1_score}%`;
  document.getElementById('metricFpr').textContent = `${s.false_positive_rate}%`;
  document.getElementById('metricThroughput').textContent = `${s.throughput_tps.toLocaleString()} tx/s`;

  document.getElementById('cmTp').textContent = cm.true_positives;
  document.getElementById('cmFn').textContent = cm.false_negatives;
  document.getElementById('cmFp').textContent = cm.false_positives;
  document.getElementById('cmTn').textContent = cm.true_negatives;

  document.getElementById('finTotalFraud').textContent = `₹${parseFloat(fin.total_fraud_attempted_inr).toLocaleString('en-IN', { minimumFractionDigits: 2 })}`;
  document.getElementById('finPreventedFraud').textContent = `₹${parseFloat(fin.fraud_loss_prevented_inr).toLocaleString('en-IN', { minimumFractionDigits: 2 })}`;
  document.getElementById('finFpCost').textContent = `₹${parseFloat(fin.false_positive_friction_cost_inr).toLocaleString('en-IN', { minimumFractionDigits: 2 })}`;
  document.getElementById('finNetBenefit').textContent = `₹${parseFloat(fin.net_economic_benefit_inr).toLocaleString('en-IN', { minimumFractionDigits: 2 })}`;

  // Update chart
  if (costChart) {
    costChart.data.datasets[0].data = [
      parseFloat(fin.total_fraud_attempted_inr),
      parseFloat(fin.fraud_loss_prevented_inr),
      parseFloat(fin.false_positive_friction_cost_inr),
      parseFloat(fin.net_economic_benefit_inr)
    ];
    costChart.update();
  }

  // Render per-class accuracy bars
  const container = document.getElementById('classAccuracyBars');
  container.innerHTML = '';
  for (const [className, stats] of Object.entries(results.class_breakdown)) {
    const formattedName = className.replace(/_/g, ' ');
    const bar = document.createElement('div');
    bar.className = 'bar-item';
    bar.innerHTML = `
      <div class="bar-meta">
        <span>${formattedName} (${stats.total_samples} samples)</span>
        <strong>${stats.accuracy}%</strong>
      </div>
      <div class="bar-track">
        <div class="bar-fill" style="width: ${stats.accuracy}%;"></div>
      </div>
    `;
    container.appendChild(bar);
  }
}

function initCostChart() {
  const ctx = document.getElementById('costBenefitChart')?.getContext('2d');
  if (!ctx) return;

  costChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['Attempted Fraud', 'Fraud Prevented', 'FP Review Cost', 'Net Benefit Saved'],
      datasets: [{
        label: 'Financial Impact (INR)',
        data: [693160, 692660, 0, 692660],
        backgroundColor: [
          'rgba(255, 51, 102, 0.65)',
          'rgba(0, 245, 155, 0.75)',
          'rgba(255, 170, 0, 0.65)',
          'rgba(0, 240, 255, 0.85)'
        ],
        borderColor: [
          '#ff3366',
          '#00f59b',
          '#ffaa00',
          '#00f0ff'
        ],
        borderWidth: 1.5,
        borderRadius: 6
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: (ctx) => `₹${ctx.raw.toLocaleString('en-IN')}`
          }
        }
      },
      scales: {
        y: {
          grid: { color: 'rgba(255, 255, 255, 0.05)' },
          ticks: { color: '#94a3b8', font: { size: 10 } }
        },
        x: {
          grid: { display: false },
          ticks: { color: '#94a3b8', font: { size: 10 } }
        }
      }
    }
  });
}

function populateDefaultBenchmarkStats() {
  const container = document.getElementById('classAccuracyBars');
  if (!container) return;
  const classes = [
    { name: 'BENIGN LEGITIMATE', acc: 100.0, total: 600 },
    { name: 'MANDATE EXCEED BUDGET', acc: 100.0, total: 100 },
    { name: 'REPLAY EXPIRED MANDATE', acc: 98.75, total: 80 },
    { name: 'VELOCITY BURST CARD TEST', acc: 98.75, total: 80 },
    { name: 'PROMPT INJECTION OVERRIDE', acc: 100.0, total: 80 },
    { name: 'OFF MANDATE CATEGORY EXFIL', acc: 100.0, total: 60 }
  ];

  container.innerHTML = '';
  classes.forEach(c => {
    const bar = document.createElement('div');
    bar.className = 'bar-item';
    bar.innerHTML = `
      <div class="bar-meta">
        <span>${c.name} (${c.total} samples)</span>
        <strong>${c.acc}%</strong>
      </div>
      <div class="bar-track">
        <div class="bar-fill" style="width: ${c.acc}%;"></div>
      </div>
    `;
    container.appendChild(bar);
  });
}

function escapeHtml(str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

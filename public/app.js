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
  const tabBtns = document.querySelectorAll('.skeuo-tab-btn');
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
    console.warn('[WS] Fallback mode:', err);
    return;
  }

  ws.onopen = () => {
    logTerminal('sys', 'Connected to Mandate Sentinel Telemetry Bus.');
    const statusText = document.getElementById('systemStatusText');
    if (statusText) statusText.textContent = 'ARMED & ACTIVE';
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
    const statusText = document.getElementById('systemStatusText');
    if (statusText) statusText.textContent = 'RECONNECTING BUS';
    setTimeout(initWebSocket, 3000);
  };
}

// 3. Trigger Adversarial Attack / Benign Purchase Simulation
async function triggerAttack(attackType) {
  logTerminal('sys', `INJECTING PAYLOAD [${attackType}] INTO GATE BUS...`);
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
  const txIdEl = document.getElementById('currentTxId');
  if (txIdEl) txIdEl.textContent = tx.tx_id || 'STANDBY_BUS_READY';

  const latencyVal = `${tx.latency_ms || 1.1} ms`;
  const latencyPill = document.getElementById('txLatencyPill');
  if (latencyPill) latencyPill.textContent = latencyVal;
  const headerLatency = document.getElementById('headerLatencyVal');
  if (headerLatency) headerLatency.textContent = latencyVal;

  // Layer 1
  const l1 = tx.inspection?.layer1;
  const l1Circle = document.getElementById('l1Circle');
  const l1Badge = document.getElementById('l1Badge');
  const l1Details = document.getElementById('l1Details');

  if (l1) {
    l1Circle.className = `rail-circle ${l1.passed ? 'pass' : 'fail'}`;
    l1Badge.className = `layer-stamp ${l1.passed ? 'pass' : 'fail'}`;
    l1Badge.textContent = l1.passed ? 'PASSED' : 'VIOLATION';
    l1Details.textContent = l1.passed
      ? `[VERIFIED] Signature valid | Cap: INR ${(l1.details.remaining_budget_paise/100).toFixed(0)} remaining | Merchant & MCC authorized`
      : `[VIOLATION] ${l1.violations.join('; ')}`;
  }

  // Layer 2
  const l2 = tx.inspection?.layer2;
  const l2Circle = document.getElementById('l2Circle');
  const l2Badge = document.getElementById('l2Badge');
  const l2Details = document.getElementById('l2Details');

  if (l2) {
    const l2Pass = !l2.anomaly_detected;
    l2Circle.className = `rail-circle ${l2Pass ? 'pass' : 'fail'}`;
    l2Badge.className = `layer-stamp ${l2Pass ? 'pass' : 'fail'}`;
    l2Badge.textContent = `RISK: ${l2.ml_risk_score}`;
    l2Details.textContent = l2Pass
      ? `[NOMINAL] Velocity score: ${l2.sub_scores.velocity_score} | Z-Score: ${l2.sub_scores.amount_z_score} | Known merchant pattern`
      : `[ANOMALY] ${l2.risk_factors.join('; ') || 'High statistical drift detected'}`;
  }

  // Layer 3
  const l3 = tx.inspection?.layer3;
  const l3Circle = document.getElementById('l3Circle');
  const l3Badge = document.getElementById('l3Badge');
  const l3Details = document.getElementById('l3Details');

  if (l3) {
    l3Circle.className = `rail-circle ${l3.passed ? 'pass' : 'fail'}`;
    l3Badge.className = `layer-stamp ${l3.passed ? 'pass' : 'fail'}`;
    l3Badge.textContent = l3.passed ? 'CLEAN' : 'TAMPERED';
    l3Details.textContent = l3.passed
      ? `[CLEAR] Zero adversarial injection patterns | Semantic intent aligned`
      : `[STRIDE THREAT] ${l3.detected_signatures.join('; ')}`;
  }

  // Master Decision Bezel
  const banner = document.getElementById('decisionBanner');
  const outcomeText = document.getElementById('decisionOutcome');
  const compositeVal = document.getElementById('compositeRiskVal');
  const reasonText = document.getElementById('decisionReason');
  const dispatchText = document.getElementById('razorpayStatusText');
  const meterFill = document.getElementById('meterFill');

  outcomeText.textContent = tx.outcome;
  compositeVal.textContent = tx.composite_risk_score.toFixed(4);
  reasonText.textContent = tx.decision_reason;

  if (meterFill) {
    const fillPct = Math.min(100, Math.max(0, tx.composite_risk_score * 100));
    meterFill.style.width = `${fillPct}%`;
  }

  const bannerClass = tx.outcome === 'ALLOW' ? 'allow' : tx.outcome === 'STEP_UP' ? 'warn' : 'block';
  banner.className = `master-decision-bezel ${bannerClass}`;

  if (tx.outcome === 'ALLOW' && tx.razorpay_order) {
    dispatchText.innerHTML = `Order Executed: <strong>${tx.razorpay_order.id}</strong> (Status: ${tx.razorpay_order.status}) &bull; <a href="${tx.razorpay_order.short_url || '#'}" target="_blank" style="color:#0284c7; text-decoration:underline;">Razorpay Checkout</a>`;
  } else if (tx.outcome === 'STEP_UP') {
    dispatchText.innerHTML = `<span style="color:#d97706; font-weight:600;">Razorpay API paused. Stepped-up to user biometric challenge.</span>`;
  } else {
    dispatchText.innerHTML = `<span style="color:#dc2626; font-weight:600;">Razorpay API blocked. Malicious transaction quarantined &amp; dropped.</span>`;
  }

  // JSON Raw Inspector
  document.getElementById('jsonInspector').textContent = JSON.stringify(tx, null, 2);

  // Append to terminal
  const logClass = tx.outcome === 'ALLOW' ? 'allow' : tx.outcome === 'STEP_UP' ? 'warn' : 'block';
  logTerminal(logClass, `[${tx.outcome}] ${tx.tx_id} | Risk: ${tx.composite_risk_score} | ${tx.decision_reason.slice(0, 80)}`);
}

function resetPipelineUI() {
  document.getElementById('l1Circle').className = 'rail-circle';
  document.getElementById('l2Circle').className = 'rail-circle';
  document.getElementById('l3Circle').className = 'rail-circle';
  document.getElementById('l1Badge').textContent = 'EVALUATING';
  document.getElementById('l2Badge').textContent = 'EVALUATING';
  document.getElementById('l3Badge').textContent = 'EVALUATING';
}

function logTerminal(type, message) {
  const logs = document.getElementById('terminalLogs');
  if (!logs) return;
  const entry = document.createElement('div');
  entry.className = `log-line ${type}`;
  const time = new Date().toLocaleTimeString();
  entry.innerHTML = `<span class="log-timestamp">[${time}]</span><span class="log-msg">${escapeHtml(message)}</span>`;
  logs.prepend(entry);
}

function clearLiveFeed() {
  const logs = document.getElementById('terminalLogs');
  if (logs) logs.innerHTML = '';
}

// 5. AP2 Mandate Studio
async function loadMandates() {
  try {
    const res = await fetch('/api/mandates');
    const data = await res.json();
    const list = document.getElementById('mandateList');
    if (!list) return;
    list.innerHTML = '';

    if (data.mandates && data.mandates.length > 0) {
      data.mandates.forEach(item => {
        const m = item.mandate;
        const card = document.createElement('div');
        card.className = 'mandate-tactile-card';
        card.innerHTML = `
          <div class="mandate-card-head">
            <span class="mandate-id-etched">${m.mandate_id}</span>
            <span class="tactile-pill pill-allow">${item.status}</span>
          </div>
          <div class="mandate-metrics-chips">
            <span class="metric-chip">Cap: <strong>INR ${(m.spend_cap_paise/100).toFixed(0)}</strong></span>
            <span class="metric-chip">Limit: <strong>INR ${(m.single_tx_limit_paise/100).toFixed(0)}</strong></span>
            <span class="metric-chip">Spent: <strong>INR ${(item.spent_paise/100).toFixed(0)}</strong></span>
            <span class="metric-chip">Agent: <strong>${m.agent_id}</strong></span>
          </div>
          <div style="font-size:0.73rem; color:var(--ink-secondary); margin-top:0.4rem;">
            Purpose: ${m.purpose}
          </div>
          <div style="margin-top:0.4rem; font-family:var(--mono); font-size:0.65rem; color:var(--ink-faint); word-break:break-all;">
            HMAC Signature: ${item.signature}
          </div>
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
      logTerminal('sys', `AP2 Mandate Token Issued: ${data.mandate.mandate.mandate_id}`);
      loadMandates();
      alert(`Mandate Token ${data.mandate.mandate.mandate_id} cryptographically signed & active.`);
    }
  } catch (err) {
    alert(`Failed to create mandate: ${err.message}`);
  }
}

// 6. Verifiable Cryptographic Audit Ledger
async function loadAuditLedger() {
  try {
    const res = await fetch('/api/audit-ledger?limit=30');
    const data = await res.json();
    const tbody = document.getElementById('auditTableBody');
    if (!tbody) return;
    tbody.innerHTML = '';

    if (data.ledger && data.ledger.length > 0) {
      data.ledger.forEach(entry => {
        const row = document.createElement('tr');
        const outcomeTag = entry.outcome === 'ALLOW' ? 'pill-allow' : entry.outcome === 'STEP_UP' ? 'pill-stepup' : 'pill-block';
        const orderText = entry.razorpay_result?.order_id || 'Quarantined';

        row.innerHTML = `
          <td><strong>#${entry.sequence}</strong></td>
          <td class="mono">${new Date(entry.timestamp).toLocaleTimeString()}</td>
          <td class="mono">${entry.tx_id}</td>
          <td>${entry.mandate_id}</td>
          <td class="mono">INR ${(entry.amount_paise/100).toFixed(2)}</td>
          <td><span class="tactile-pill ${outcomeTag}">${entry.outcome}</span></td>
          <td class="mono">${entry.composite_risk_score.toFixed(4)}</td>
          <td class="mono">${orderText}</td>
          <td><span class="hash-etched-pill" title="SHA-256 Block Hash: ${entry.node_hash}">${entry.node_hash.slice(0, 14)}...</span></td>
        `;
        tbody.appendChild(row);
      });
    }
  } catch (err) {
    console.error('Failed to load audit ledger:', err);
  }
}

// 7. Adversarial Benchmark Runner
async function executeBenchmark() {
  const btn = document.getElementById('runBenchmarkBtn');
  btn.disabled = true;
  btn.innerHTML = `<span>Running 1,000 Samples...</span>`;

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
    btn.innerHTML = `
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <polygon points="5 3 19 12 5 21 5 3"/>
      </svg>
      <span>Run 1,000-Sample Benchmark</span>
    `;
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
  if (!container) return;
  container.innerHTML = '';
  for (const [className, stats] of Object.entries(results.class_breakdown)) {
    const formattedName = className.replace(/_/g, ' ');
    const bar = document.createElement('div');
    bar.className = 'acc-bar-row';
    bar.innerHTML = `
      <span class="acc-bar-label">${formattedName} (${stats.total_samples})</span>
      <div class="acc-bar-track"><div class="acc-bar-fill" style="width: ${stats.accuracy}%;"></div></div>
      <span class="acc-bar-pct">${stats.accuracy}%</span>
    `;
    container.appendChild(bar);
  }
}

function initCostChart() {
  const canvas = document.getElementById('costBenefitChart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  costChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['Attempted Fraud', 'Fraud Prevented', 'FP Review Friction', 'Net Value Preserved'],
      datasets: [{
        label: 'Financial Impact (INR)',
        data: [693160, 692660, 0, 692660],
        backgroundColor: [
          'rgba(239, 68, 68, 0.15)',
          'rgba(16, 185, 129, 0.18)',
          'rgba(245, 158, 11, 0.15)',
          'rgba(15, 23, 42, 0.18)'
        ],
        borderColor: [
          '#ef4444',
          '#10b981',
          '#f59e0b',
          '#0f172a'
        ],
        borderWidth: 1.5,
        borderRadius: 4
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
          grid: { color: 'rgba(0, 0, 0, 0.05)' },
          ticks: { color: '#64748b', font: { size: 10 } }
        },
        x: {
          grid: { display: false },
          ticks: { color: '#64748b', font: { size: 10 } }
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
    bar.className = 'acc-bar-row';
    bar.innerHTML = `
      <span class="acc-bar-label">${c.name} (${c.total})</span>
      <div class="acc-bar-track"><div class="acc-bar-fill" style="width: ${c.acc}%;"></div></div>
      <span class="acc-bar-pct">${c.acc}%</span>
    `;
    container.appendChild(bar);
  });
}

function escapeHtml(str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

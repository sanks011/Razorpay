import { mandateStore } from '../mandate_protocol/mandate_store.js';

/**
 * Layer 2: ML & Statistical Anomaly Scorer
 * Detects velocity bursts (card testing), sudden amount spikes (Z-score),
 * merchant drift, and abnormal temporal behavior.
 */
export function evaluateLayer2MLAnomaly(request, mandatePayload) {
  const {
    agent_id = 'default_agent',
    amount_paise,
    merchant_id,
    mcc_category,
    request_timestamp = Date.now()
  } = request;

  const history = mandateStore.getAgentHistory(agent_id);
  const now = request_timestamp;

  // 1. Velocity Analysis (Card Testing & Rapid Micro-Tx Detection)
  // Window: Last 60 seconds and Last 5 minutes
  const window1Min = 60 * 1000;
  const window5Min = 5 * 60 * 1000;

  const txs1Min = history.filter(tx => Math.abs(now - tx.timestamp) <= window1Min);
  const txs5Min = history.filter(tx => Math.abs(now - tx.timestamp) <= window5Min);

  let velocityScore = 0.05;
  let velocityRiskFactor = 'NORMAL';

  if (txs1Min.length >= 3) {
    velocityScore = 0.95; // Extreme card-testing burst
    velocityRiskFactor = `CRITICAL_BURST: ${txs1Min.length + 1} txns in 60s window`;
  } else if (txs1Min.length >= 1) {
    velocityScore = 0.75;
    velocityRiskFactor = `HIGH_VELOCITY: ${txs1Min.length + 1} txns in 60s window`;
  } else if (txs5Min.length >= 4) {
    velocityScore = 0.60;
    velocityRiskFactor = `ELEVATED_VELOCITY: ${txs5Min.length + 1} txns in 5m window`;
  }

  // 2. Amount Anomaly & Z-Score Analysis
  let amountZScore = 0.0;
  let amountScore = 0.05;
  let amountExplanation = 'Within normal baseline';

  if (history.length >= 3) {
    const amounts = history.map(tx => tx.amount_paise);
    const mean = amounts.reduce((sum, val) => sum + val, 0) / amounts.length;
    const variance = amounts.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / amounts.length;
    const stdDev = Math.sqrt(variance) || (mean * 0.2);

    amountZScore = (amount_paise - mean) / stdDev;

    if (amountZScore > 3.0) {
      amountScore = 0.85;
      amountExplanation = `EXTREME_AMOUNT_SPIKE: Z-score +${amountZScore.toFixed(2)} vs historical mean ₹${(mean/100).toFixed(2)}`;
    } else if (amountZScore > 2.0) {
      amountScore = 0.60;
      amountExplanation = `NOTABLE_AMOUNT_DEVIATION: Z-score +${amountZScore.toFixed(2)}`;
    } else if (amountZScore > 1.2) {
      amountScore = 0.25;
      amountExplanation = `MILD_AMOUNT_INCREASE: Z-score +${amountZScore.toFixed(2)}`;
    }
  } else {
    // Cold start within reasonable mandate bounds
    if (mandatePayload && amount_paise > (mandatePayload.single_tx_limit_paise * 0.90)) {
      amountScore = 0.20;
      amountExplanation = 'Near single-transaction ceiling on initial interaction';
    }
  }

  // 3. Merchant & Category Drift
  let merchantDriftScore = 0.05;
  let merchantExplanation = 'Known or explicitly authorized merchant';

  const isExplicitlyAllowlisted = mandatePayload &&
    Array.isArray(mandatePayload.allowed_merchants) &&
    (mandatePayload.allowed_merchants.includes('*') || mandatePayload.allowed_merchants.includes(merchant_id));

  if (!isExplicitlyAllowlisted) {
    if (history.length > 0) {
      const seenMerchants = new Set(history.map(tx => tx.merchant_id));
      if (!seenMerchants.has(merchant_id)) {
        merchantDriftScore = 0.40;
        merchantExplanation = `NOVEL_MERCHANT: First interaction by agent with '${merchant_id}'`;
      }
    }
  }

  // 4. Temporal Pattern (mild auxiliary signal)
  const dateObj = new Date(now);
  const hour = dateObj.getHours();
  let temporalScore = 0.05;
  if (hour >= 1 && hour <= 4) {
    temporalScore = 0.15;
  }

  // Composite ML score takes the maximum of high individual risk signals or blended average
  const maxDirectSignal = Math.max(velocityScore, amountScore);
  const compositeScore = Math.max(
    maxDirectSignal,
    velocityScore * 0.45 + amountScore * 0.35 + merchantDriftScore * 0.10 + temporalScore * 0.10
  );

  const riskFactors = [];
  if (velocityScore >= 0.5) riskFactors.push(velocityRiskFactor);
  if (amountScore >= 0.5) riskFactors.push(amountExplanation);
  if (merchantDriftScore >= 0.3) riskFactors.push(merchantExplanation);
  if (temporalScore >= 0.3) riskFactors.push(`UNUSUAL_HOURS: Transaction initiated at ${hour}:00`);

  return {
    layer: 'LAYER_2_ML_STATISTICAL_ANOMALY',
    ml_risk_score: parseFloat(compositeScore.toFixed(4)),
    sub_scores: {
      velocity_score: parseFloat(velocityScore.toFixed(4)),
      amount_z_score: parseFloat(amountZScore.toFixed(2)),
      amount_anomaly_score: parseFloat(amountScore.toFixed(4)),
      merchant_drift_score: parseFloat(merchantDriftScore.toFixed(4)),
      temporal_score: parseFloat(temporalScore.toFixed(4))
    },
    risk_factors: riskFactors,
    anomaly_detected: compositeScore >= 0.50
  };
}

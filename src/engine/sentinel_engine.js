import { evaluateLayer1Mandate } from '../defense_layers/layer1_deterministic.js';
import { evaluateLayer2MLAnomaly } from '../defense_layers/layer2_ml_anomaly.js';
import { evaluateLayer3PromptGuard } from '../defense_layers/layer3_prompt_guard.js';
import { DecisionOutcome } from '../mandate_protocol/types.js';
import { mandateStore } from '../mandate_protocol/mandate_store.js';
import { razorpayClient } from '../razorpay/razorpay_client.js';
import { generateJti } from '../mandate_protocol/crypto.js';

export class SentinelEngine {
  constructor(options = {}) {
    this.listeners = new Set();
    this.allowThreshold = options.allowThreshold || 0.35;
    this.blockThreshold = options.blockThreshold || 0.70;
  }

  onEvent(callback) {
    this.listeners.add(callback);
    return () => this.listeners.delete(callback);
  }

  _emit(event) {
    for (const listener of this.listeners) {
      try {
        listener(event);
      } catch (err) {
        console.error('[SentinelEngine] Listener error:', err);
      }
    }
  }

  /**
   * Main verification & gating pipeline
   */
  async processTransaction(request) {
    const startTime = Date.now();
    const txId = request.tx_id || 'tx_agt_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 7);
    const jti = request.jti || generateJti();
    const amountPaise = parseInt(request.amount_paise, 10) || 0;

    const enrichedRequest = {
      ...request,
      tx_id: txId,
      jti,
      amount_paise: amountPaise,
      request_timestamp: request.request_timestamp || Date.now()
    };

    // 1. Fetch mandate metadata for Layer 3 context
    const mandateEntry = mandateStore.getMandate(request.mandate_id);
    const mandatePayload = request.mandate_payload || (mandateEntry ? mandateEntry.mandate : null);

    // 2. Execute 3-Layer Defense Inspection
    const l1Result = evaluateLayer1Mandate(enrichedRequest);
    const l2Result = evaluateLayer2MLAnomaly(enrichedRequest, mandatePayload);
    const l3Result = evaluateLayer3PromptGuard(enrichedRequest, mandatePayload);

    // 3. Compute Composite Risk Score & Policy Decision
    let finalOutcome = DecisionOutcome.ALLOW;
    let decisionReason = 'All mandate boundaries verified. Risk within safe threshold.';
    let compositeRisk = 0.0;

    if (!l1Result.passed) {
      finalOutcome = DecisionOutcome.BLOCK;
      compositeRisk = 1.0;
      decisionReason = `HARD_MANDATE_VIOLATION: ${l1Result.violations.join('; ')}`;
    } else {
      // Risk synthesis: if either ML anomaly or Prompt tampering is severe, reflect high composite risk
      const mlRisk = l2Result.ml_risk_score;
      const promptRisk = l3Result.prompt_risk_score;
      
      // Dominant risk score + complementary signals
      compositeRisk = Math.max(mlRisk, promptRisk, (mlRisk * 0.5 + promptRisk * 0.5));
      compositeRisk = parseFloat(Math.min(1.0, compositeRisk).toFixed(4));

      if (l3Result.tampering_detected || compositeRisk >= this.blockThreshold) {
        finalOutcome = DecisionOutcome.BLOCK;
        const reasons = [...l1Result.violations, ...l2Result.risk_factors, ...l3Result.detected_signatures];
        decisionReason = `SECURITY_RISK_BLOCK: ${reasons.join('; ') || 'High composite anomaly score'}`;
      } else if (compositeRisk >= this.allowThreshold) {
        finalOutcome = DecisionOutcome.STEP_UP;
        const reasons = [...l2Result.risk_factors, ...l3Result.detected_signatures];
        decisionReason = `STEP_UP_REQUIRED: Elevated risk pattern detected (${reasons.join(', ') || 'Score: ' + compositeRisk}). Biometric/OTP challenge required.`;
      }
    }

    // 4. Execution on Razorpay API (Only if ALLOWed)
    let razorpayResponse = null;
    let executionError = null;

    if (finalOutcome === DecisionOutcome.ALLOW) {
      try {
        if (request.action === 'create_payment_link') {
          razorpayResponse = await razorpayClient.createPaymentLink({
            amount: amountPaise,
            currency: request.currency || 'INR',
            customer: request.customer || {},
            description: request.description || 'Agent purchase',
            notes: {
              mandate_id: request.mandate_id,
              tx_id: txId,
              agent_id: request.agent_id
            }
          });
        } else {
          razorpayResponse = await razorpayClient.createOrder({
            amount: amountPaise,
            currency: request.currency || 'INR',
            receipt: `rcpt_${txId}`,
            notes: {
              mandate_id: request.mandate_id,
              tx_id: txId,
              agent_id: request.agent_id,
              agent_reasoning: request.agent_reasoning || 'Autonomous purchase'
            }
          });
        }

        mandateStore.recordSpent(request.mandate_id, amountPaise);
        mandateStore.markJtiUsed(jti);
      } catch (err) {
        executionError = err.message;
      }
    }

    // Record in historical sliding window for agent
    mandateStore.recordHistoricalTx(request.agent_id || 'default_agent', {
      timestamp: enrichedRequest.request_timestamp,
      amount_paise: amountPaise,
      merchant_id: request.merchant_id,
      mcc_category: request.mcc_category,
      outcome: finalOutcome
    });

    const latencyMs = Date.now() - startTime;

    // 5. Generate Cryptographic Audit Trail Node
    const auditRecord = {
      tx_id: txId,
      jti,
      mandate_id: request.mandate_id,
      agent_id: request.agent_id || 'agt_claude_assistant',
      merchant_id: request.merchant_id,
      amount_paise: amountPaise,
      currency: request.currency || 'INR',
      outcome: finalOutcome,
      composite_risk_score: compositeRisk,
      decision_reason: decisionReason,
      layers: {
        l1_deterministic: l1Result,
        l2_ml_anomaly: l2Result,
        l3_prompt_guard: l3Result
      },
      razorpay_result: razorpayResponse ? {
        order_id: razorpayResponse.id,
        status: razorpayResponse.status,
        short_url: razorpayResponse.short_url || null
      } : null,
      latency_ms: latencyMs
    };

    const auditNode = mandateStore.appendAuditLog(auditRecord);

    const fullResponse = {
      success: finalOutcome === DecisionOutcome.ALLOW,
      tx_id: txId,
      mandate_id: request.mandate_id,
      outcome: finalOutcome,
      composite_risk_score: compositeRisk,
      decision_reason: decisionReason,
      razorpay_order: razorpayResponse,
      audit_proof: {
        node_hash: auditNode.node_hash,
        prev_hash: auditNode.prev_hash,
        sequence: auditNode.sequence
      },
      inspection: {
        layer1: l1Result,
        layer2: l2Result,
        layer3: l3Result
      },
      latency_ms: latencyMs
    };

    this._emit({
      type: 'TRANSACTION_EVALUATED',
      data: fullResponse
    });

    return fullResponse;
  }
}

export const sentinelEngine = new SentinelEngine();

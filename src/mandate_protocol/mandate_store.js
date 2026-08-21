import { signMandate, generateMandateId, generateJti, computeAuditNodeHash } from './crypto.js';
import { createMandate, MandateScope, MerchantCategoryCodes } from './types.js';

/**
 * State store for Mandate Sentinel:
 * - Active mandates with spent counters
 * - Nonce/JTI cache for replay protection
 * - Agent historical transaction sliding windows (for ML velocity/Z-score)
 * - Cryptographic tamper-evident audit ledger
 */
class MandateStore {
  constructor() {
    this.mandates = new Map();         // mandate_id -> { mandate, signature, spent_paise, created_at, status }
    this.usedJtis = new Map();         // jti -> timestamp
    this.agentHistory = new Map();     // agent_id -> array of { timestamp, amount_paise, merchant_id, category, outcome }
    this.auditLedger = [];             // array of chained audit logs
    this.lastAuditHash = '0000000000000000000000000000000000000000000000000000000000000000'; // Genesis block hash
    
    this._initializeDemoMandates();
  }

  _initializeDemoMandates() {
    // 1. Standard Daily Groceries & Food Mandate (AP2 / UPI Reserve Pay)
    const foodMandatePayload = createMandate({
      mandate_id: 'mnd_ap2_grocery_demo_01',
      user_id: 'usr_sankalpa_99',
      agent_id: 'agt_claude_groceries',
      scope: MandateScope.DELEGATED_TASK,
      spend_cap_paise: 500000,        // ₹5,000.00
      single_tx_limit_paise: 150000,  // ₹1,500.00
      allowed_merchants: ['mer_zepto_delhi', 'mer_blinkit_gurgaon', 'mer_zomato_in', 'mer_swiggy_in', 'mer_star_market'],
      allowed_categories: [MerchantCategoryCodes.FOOD_DELIVERY, MerchantCategoryCodes.GROCERY_SUPERMARKET],
      purpose: 'Authorized weekly grocery & daily food delivery assistant'
    });
    const foodSig = signMandate(foodMandatePayload);
    this.registerMandate(foodMandatePayload, foodSig);

    // 2. High-Capacity Travel Booking Mandate
    const travelMandatePayload = createMandate({
      mandate_id: 'mnd_ap2_travel_exec_02',
      user_id: 'usr_sankalpa_99',
      agent_id: 'agt_cursor_travel_pilot',
      scope: MandateScope.REAL_TIME_PURCHASE,
      spend_cap_paise: 2500000,       // ₹25,000.00
      single_tx_limit_paise: 1500000, // ₹15,000.00
      allowed_merchants: ['mer_makemytrip_in', 'mer_indigo_air', 'mer_uber_india'],
      allowed_categories: [MerchantCategoryCodes.TRANSPORT_TRAVEL],
      purpose: 'Flight and cab booking agent for Bangalore conference'
    });
    const travelSig = signMandate(travelMandatePayload);
    this.registerMandate(travelMandatePayload, travelSig);

    // Pre-populate realistic benign historical transactions for ML baselines
    const now = Date.now();
    this.recordHistoricalTx('agt_claude_groceries', {
      timestamp: now - 3600000 * 24 * 3,
      amount_paise: 42000, // ₹420
      merchant_id: 'mer_zepto_delhi',
      category: MerchantCategoryCodes.GROCERY_SUPERMARKET,
      outcome: 'ALLOW'
    });
    this.recordHistoricalTx('agt_claude_groceries', {
      timestamp: now - 3600000 * 24 * 2,
      amount_paise: 68000, // ₹680
      merchant_id: 'mer_blinkit_gurgaon',
      category: MerchantCategoryCodes.GROCERY_SUPERMARKET,
      outcome: 'ALLOW'
    });
    this.recordHistoricalTx('agt_claude_groceries', {
      timestamp: now - 3600000 * 24 * 1,
      amount_paise: 35000, // ₹350
      merchant_id: 'mer_zomato_in',
      category: MerchantCategoryCodes.FOOD_DELIVERY,
      outcome: 'ALLOW'
    });
  }

  registerMandate(mandate, signature) {
    this.mandates.set(mandate.mandate_id, {
      mandate,
      signature,
      spent_paise: 0,
      created_at: new Date().toISOString(),
      status: 'ACTIVE'
    });
    return this.mandates.get(mandate.mandate_id);
  }

  getMandate(mandateId) {
    return this.mandates.get(mandateId);
  }

  getAllMandates() {
    return Array.from(this.mandates.values());
  }

  recordSpent(mandateId, amountPaise) {
    const entry = this.mandates.get(mandateId);
    if (entry) {
      entry.spent_paise += amountPaise;
      if (entry.spent_paise >= entry.mandate.spend_cap_paise) {
        entry.status = 'EXHAUSTED';
      }
    }
  }

  hasUsedJti(jti) {
    if (!jti) return false;
    return this.usedJtis.has(jti);
  }

  markJtiUsed(jti, ttlMs = 86400000) {
    if (!jti) return;
    this.usedJtis.set(jti, Date.now() + ttlMs);
  }

  recordHistoricalTx(agentId, txData) {
    if (!this.agentHistory.has(agentId)) {
      this.agentHistory.set(agentId, []);
    }
    const list = this.agentHistory.get(agentId);
    list.push(txData);
    // Keep sliding window of last 200 transactions
    if (list.length > 200) {
      list.shift();
    }
  }

  getAgentHistory(agentId) {
    return this.agentHistory.get(agentId) || [];
  }

  appendAuditLog(auditRecord) {
    const timestamp = new Date().toISOString();
    const prevHash = this.lastAuditHash;
    const nodePayload = {
      ...auditRecord,
      timestamp,
      prev_hash: prevHash
    };
    const nodeHash = computeAuditNodeHash(prevHash, nodePayload);
    const completeEntry = {
      ...nodePayload,
      node_hash: nodeHash,
      sequence: this.auditLedger.length + 1
    };
    this.auditLedger.unshift(completeEntry); // Newest first
    if (this.auditLedger.length > 1000) {
      this.auditLedger.pop();
    }
    this.lastAuditHash = nodeHash;
    return completeEntry;
  }

  getAuditLedger(limit = 50) {
    return this.auditLedger.slice(0, limit);
  }

  resetState() {
    this.mandates.clear();
    this.usedJtis.clear();
    this.agentHistory.clear();
    this.auditLedger = [];
    this.lastAuditHash = '0000000000000000000000000000000000000000000000000000000000000000';
    this._initializeDemoMandates();
  }
}

export const mandateStore = new MandateStore();

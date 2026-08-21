import { verifyMandateSignature } from '../mandate_protocol/crypto.js';
import { mandateStore } from '../mandate_protocol/mandate_store.js';

/**
 * Layer 1: Deterministic Mandate Verification (AP2 / NPCI UAP Specification)
 * Zero-ambiguity hard constraint evaluation.
 */
export function evaluateLayer1Mandate(request) {
  const {
    mandate_id,
    mandate_payload,
    mandate_signature,
    jti,
    amount_paise,
    merchant_id,
    mcc_category,
    request_timestamp = Date.now()
  } = request;

  const result = {
    layer: 'LAYER_1_DETERMINISTIC_MANDATE',
    passed: true,
    violations: [],
    details: {
      signature_valid: false,
      replay_detected: false,
      budget_ok: true,
      single_tx_ok: true,
      merchant_ok: true,
      category_ok: true,
      time_window_ok: true,
      remaining_budget_paise: 0
    }
  };

  // 1. Check Mandate Existence in Registry or Payload
  let mandateEntry = mandateStore.getMandate(mandate_id);
  let mandateData = mandate_payload || (mandateEntry ? mandateEntry.mandate : null);
  let sigToVerify = mandate_signature || (mandateEntry ? mandateEntry.signature : null);

  if (!mandateData || !sigToVerify) {
    result.passed = false;
    result.violations.push('MANDATE_NOT_FOUND_OR_MISSING_SIGNATURE');
    return result;
  }

  // 2. Cryptographic Signature Verification
  const isSigValid = verifyMandateSignature(mandateData, sigToVerify);
  result.details.signature_valid = isSigValid;
  if (!isSigValid) {
    result.passed = false;
    result.violations.push('INVALID_MANDATE_CRYPTOGRAPHIC_SIGNATURE');
  }

  // 3. Replay Protection (JTI / Nonce check)
  if (jti) {
    if (mandateStore.hasUsedJti(jti)) {
      result.passed = false;
      result.details.replay_detected = true;
      result.violations.push(`REPLAY_ATTACK_DETECTED_JTI_ALREADY_USED:${jti}`);
    }
  }

  // 4. Time Window & Expiry Verification
  const now = new Date(request_timestamp);
  const validFrom = new Date(mandateData.valid_from);
  const validUntil = new Date(mandateData.valid_until);

  if (now < validFrom) {
    result.passed = false;
    result.details.time_window_ok = false;
    result.violations.push(`MANDATE_NOT_YET_VALID: Valid from ${mandateData.valid_from}`);
  } else if (now > validUntil) {
    result.passed = false;
    result.details.time_window_ok = false;
    result.violations.push(`MANDATE_EXPIRED: Expired at ${mandateData.valid_until}`);
  }

  // Check allowed hours of day (if specified)
  if (mandateData.allowed_hours) {
    const currentHour = now.getHours();
    const { start, end } = mandateData.allowed_hours;
    if (start !== undefined && end !== undefined) {
      if (currentHour < start || currentHour > end) {
        result.passed = false;
        result.details.time_window_ok = false;
        result.violations.push(`TRANSACTION_OUTSIDE_ALLOWED_HOURS: Current hour ${currentHour} not in [${start}, ${end}]`);
      }
    }
  }

  // 5. Single-Transaction Ceiling Check
  if (amount_paise > mandateData.single_tx_limit_paise) {
    result.passed = false;
    result.details.single_tx_ok = false;
    result.violations.push(
      `SINGLE_TX_LIMIT_EXCEEDED: Requested ₹${(amount_paise/100).toFixed(2)} exceeds limit ₹${(mandateData.single_tx_limit_paise/100).toFixed(2)}`
    );
  }

  // 6. Cumulative Spend Cap Check
  const currentSpent = mandateEntry ? mandateEntry.spent_paise : 0;
  const remainingBudget = Math.max(0, mandateData.spend_cap_paise - currentSpent);
  result.details.remaining_budget_paise = remainingBudget;

  if (currentSpent + amount_paise > mandateData.spend_cap_paise) {
    result.passed = false;
    result.details.budget_ok = false;
    result.violations.push(
      `CUMULATIVE_SPEND_CAP_EXCEEDED: Spent ₹${(currentSpent/100).toFixed(2)} + Request ₹${(amount_paise/100).toFixed(2)} > Cap ₹${(mandateData.spend_cap_paise/100).toFixed(2)}`
    );
  }

  // 7. Merchant Allowlist Check
  if (mandateData.allowed_merchants && !mandateData.allowed_merchants.includes('*')) {
    if (!merchant_id || !mandateData.allowed_merchants.includes(merchant_id)) {
      result.passed = false;
      result.details.merchant_ok = false;
      result.violations.push(`MERCHANT_NOT_IN_ALLOWLIST: '${merchant_id || 'UNKNOWN'}' not in authorized merchants list`);
    }
  }

  // 8. Category Allowlist Check (e.g., MCC code)
  if (mandateData.allowed_categories && mandateData.allowed_categories.length > 0) {
    if (!mcc_category || !mandateData.allowed_categories.includes(mcc_category)) {
      result.passed = false;
      result.details.category_ok = false;
      result.violations.push(`CATEGORY_NOT_AUTHORIZED: MCC '${mcc_category || 'UNKNOWN'}' is not allowed in mandate`);
    }
  }

  return result;
}

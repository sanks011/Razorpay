/**
 * Layer 3: Prompt-Injection & Intent Tamper Guard
 * Aligned with the Cloud Security Alliance (CSA) STRIDE Threat Framework for AP2/UAP.
 * Protects against agent jailbreaks, parameter overrides, hidden payload injection,
 * and semantic divergence between declared user intent and actual tool parameters.
 */

// Known adversarial patterns & override attack vectors
const INJECTION_PATTERNS = [
  /(?:ignore|disregard|forget|override|bypass)\s+(?:previous|all|the|prior|above)\s+(?:instructions|rules|mandate|budget|limits?|security)/i,
  /(?:system\s*override|admin\s*mode|developer\s*mode|jailbreak|dan\s*mode)/i,
  /(?:new\s*budget|increase\s*limit|unlimited\s*funds|set\s*spend\s*cap\s*to)/i,
  /(?:send|transfer|pay|deposit)\s+(?:to|towards)\s+(?:attacker|crypto|private\s*key|unauthorized|personal)/i,
  /(?:<!--|<instructions>|<\/instructions>|\[INST\]|\[\/INST\]|<<SYS>>|<\/s>|```system)/i,
  /(?:eval\(|exec\(|<script>|javascript:|data:text\/html)/i,
  /(?:base64|b64decode|atob)\s*[:=]\s*[A-Za-z0-9+/=]{20,}/i
];

// High-risk abuse/exfiltration target keywords in agent checkout descriptions
const EXFILTRATION_KEYWORDS = [
  'gift card', 'steam voucher', 'amazon pay gift', 'apple gift card',
  'google play code', 'crypto', 'bitcoin', 'usdt', 'tether', 'ethereum',
  'hawala', 'casino', 'betting', 'p2p voucher', 'anonymous topup', 'prepaid mastercard'
];

// Semantic keyword mapping to verify purpose consistency
const CATEGORY_KEYWORDS = {
  groceries: ['grocery', 'food', 'vegetables', 'fruits', 'milk', 'bread', 'zepto', 'blinkit', 'instamart', 'snacks', 'meal', 'dinner', 'lunch'],
  travel: ['flight', 'hotel', 'cab', 'taxi', 'train', 'indigo', 'uber', 'ola', 'makemytrip', 'airfare', 'booking'],
  utility: ['electricity', 'water', 'broadband', 'wifi', 'bill', 'recharge', 'gas', 'postpaid']
};

/**
 * Checks for zero-width Unicode injection and obfuscation characters
 */
function checkZeroWidthObfuscation(text) {
  const zeroWidthRegex = /[\u200B-\u200D\uFEFF\u202A-\u202E\u00AD]/;
  return zeroWidthRegex.test(text);
}

/**
 * Evaluates semantic divergence between mandate declared purpose and purchase description
 */
function evaluateSemanticAlignment(mandatePurpose = '', itemDescription = '') {
  if (!mandatePurpose || !itemDescription) return 0.0;
  
  const purposeLower = mandatePurpose.toLowerCase();
  const itemLower = itemDescription.toLowerCase();

  // If mandate is explicitly groceries, but item description contains luxury electronics or jewelry
  const isGroceryMandate = purposeLower.includes('grocery') || purposeLower.includes('food');
  const isTravelMandate = purposeLower.includes('travel') || purposeLower.includes('flight');

  if (isGroceryMandate) {
    if (itemLower.includes('macbook') || itemLower.includes('iphone') || itemLower.includes('gold') || itemLower.includes('diamond')) {
      return 0.85; // High semantic drift
    }
  }

  if (isTravelMandate) {
    if (itemLower.includes('crypto') || itemLower.includes('gift card') || itemLower.includes('gaming console')) {
      return 0.90;
    }
  }

  return 0.05; // Normal alignment
}

export function evaluateLayer3PromptGuard(request, mandatePayload) {
  const {
    description = '',
    customer_notes = '',
    agent_reasoning = '',
    line_items = []
  } = request;

  // Aggregate all untrusted text inputs passed from LLM agent
  const combinedUntrustedText = [
    description,
    customer_notes,
    agent_reasoning,
    Array.isArray(line_items) ? line_items.map(i => `${i.name || ''} ${i.description || ''}`).join(' ') : ''
  ].filter(Boolean).join(' | ');

  const detectedSignatures = [];
  let injectionScore = 0.0;

  // 1. Regex & Pattern Matching for Jailbreak / Mandate Override
  for (const pattern of INJECTION_PATTERNS) {
    if (pattern.test(combinedUntrustedText)) {
      detectedSignatures.push(`PROMPT_INJECTION_PATTERN_MATCH: ${pattern.toString()}`);
      injectionScore = Math.max(injectionScore, 0.92);
    }
  }

  // 2. Zero-Width Unicode Obfuscation
  if (checkZeroWidthObfuscation(combinedUntrustedText)) {
    detectedSignatures.push('ZERO_WIDTH_UNICODE_OBFUSCATION_DETECTED');
    injectionScore = Math.max(injectionScore, 0.88);
  }

  // 3. Exfiltration Keyword Detection (Gift cards, Crypto, etc.)
  const lowerText = combinedUntrustedText.toLowerCase();
  for (const keyword of EXFILTRATION_KEYWORDS) {
    if (lowerText.includes(keyword)) {
      detectedSignatures.push(`HIGH_RISK_EXFILTRATION_TARGET: '${keyword}'`);
      injectionScore = Math.max(injectionScore, 0.80);
    }
  }

  // 4. Semantic Purpose Alignment
  const mandatePurpose = mandatePayload ? mandatePayload.purpose : '';
  const semanticDriftScore = evaluateSemanticAlignment(mandatePurpose, combinedUntrustedText);
  if (semanticDriftScore >= 0.70) {
    detectedSignatures.push(`SEMANTIC_DIVERGENCE_HIGH: Mandate purpose '${mandatePurpose}' vs Item text '${combinedUntrustedText.slice(0, 60)}...'`);
    injectionScore = Math.max(injectionScore, semanticDriftScore);
  }

  const passed = injectionScore < 0.40;

  return {
    layer: 'LAYER_3_PROMPT_INJECTION_INTENT_GUARD',
    prompt_risk_score: parseFloat(injectionScore.toFixed(4)),
    passed,
    detected_signatures: detectedSignatures,
    tampering_detected: !passed,
    semantic_drift_score: parseFloat(semanticDriftScore.toFixed(4))
  };
}

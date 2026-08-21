/**
 * Standard Types & Enums for Mandate Sentinel, AP2 Protocol & NPCI UAP
 */

export const MandateScope = {
  REAL_TIME_PURCHASE: 'REAL_TIME_PURCHASE',   // Immediate single or multi-step checkout
  DELEGATED_TASK: 'DELEGATED_TASK',           // Autonomous continuous shopping agent
  RECURRING_SUBSCRIPTION: 'RECURRING_SUB',   // Periodic bounded subscription
  RESERVE_PAY: 'UPI_RESERVE_PAY'             // NPCI UPI spend reservation
};

export const DecisionOutcome = {
  ALLOW: 'ALLOW',       // Risk score < 0.35, passes all layers -> executed on Razorpay
  STEP_UP: 'STEP_UP',   // 0.35 <= Risk < 0.70 -> requires biometric / user MFA approval
  BLOCK: 'BLOCK'        // Risk >= 0.70 or hard violation -> immediately isolated & dropped
};

export const AttackCategory = {
  BENIGN_LEGITIMATE: 'BENIGN_LEGITIMATE',
  MANDATE_EXCEED_BUDGET: 'MANDATE_EXCEED_BUDGET',
  REPLAY_EXPIRED_MANDATE: 'REPLAY_EXPIRED_MANDATE',
  VELOCITY_BURST_CARD_TEST: 'VELOCITY_BURST_CARD_TEST',
  PROMPT_INJECTION_OVERRIDE: 'PROMPT_INJECTION_OVERRIDE',
  OFF_MANDATE_CATEGORY_EXFIL: 'OFF_MANDATE_CATEGORY_EXFIL'
};

export const MerchantCategoryCodes = {
  FOOD_DELIVERY: '5812',     // Zomato, Swiggy, Zepto
  GROCERY_SUPERMARKET: '5411', // BigBasket, Blinkit, Instamart
  DIGITAL_GOODS: '5815',     // Software, ebooks
  TRANSPORT_TRAVEL: '4121',  // Uber, Ola, MakeMyTrip
  UTILITY_BILLS: '4900',     // Electricity, water, broadband
  GIFT_CARDS_VOUCHERS: '5947', // High risk / abuse target
  CRYPTO_FOREX: '6051',       // High risk / strictly restricted
  JEWELRY_PRECIOUS: '5094'    // High risk / high value
};

/**
 * Creates a standard AP2 / UAP Mandate Object
 */
export function createMandate({
  mandate_id,
  user_id = 'usr_user_demo_01',
  agent_id = 'agt_claude_assistant',
  scope = MandateScope.DELEGATED_TASK,
  spend_cap_paise = 500000,         // ₹5,000.00
  single_tx_limit_paise = 200000,   // ₹2,000.00
  currency = 'INR',
  allowed_merchants = ['*'],        // '*' or specific list ['mer_zomato_123', 'mer_zepto_456']
  allowed_categories = [
    MerchantCategoryCodes.FOOD_DELIVERY,
    MerchantCategoryCodes.GROCERY_SUPERMARKET,
    MerchantCategoryCodes.TRANSPORT_TRAVEL,
    MerchantCategoryCodes.UTILITY_BILLS
  ],
  valid_from = new Date().toISOString(),
  valid_until = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(), // 24 hrs
  allowed_hours = { start: 6, end: 23 }, // 6 AM to 11 PM
  purpose = 'Authorized daily groceries & food delivery assistant budget'
}) {
  return {
    mandate_id,
    user_id,
    agent_id,
    scope,
    spend_cap_paise,
    single_tx_limit_paise,
    currency,
    allowed_merchants,
    allowed_categories,
    valid_from,
    valid_until,
    allowed_hours,
    purpose
  };
}

import crypto from 'crypto';

/**
 * AP2 (Agent Payments Protocol) & NPCI UAP Cryptographic Utilities
 * Provides canonical serialization, signature generation, signature verification,
 * and SHA-256 hash chaining for immutable audit trails.
 */

// Default secret for HMAC demo mode (in production, asymmetric ECDSA / Ed25519 is used)
const DEFAULT_SECRET_KEY = process.env.MANDATE_SENTINEL_SECRET || 'sentinel_master_key_ap2_2026_uap';

/**
 * Canonicalizes a mandate object (sorted keys, stable formatting)
 * to ensure deterministic cryptographic hash and signature validation.
 */
export function canonicalize(obj) {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(item => canonicalize(item)).join(',') + ']';
  }
  const sortedKeys = Object.keys(obj).sort();
  const pairs = sortedKeys
    .filter(k => k !== 'signature' && k !== 'client_signature' && obj[k] !== undefined)
    .map(k => `"${k}":${canonicalize(obj[k])}`);
  return '{' + pairs.join(',') + '}';
}

/**
 * Calculates SHA-256 digest of any payload
 */
export function sha256(data) {
  const content = typeof data === 'string' ? data : canonicalize(data);
  return crypto.createHash('sha256').update(content).digest('hex');
}

/**
 * Signs a mandate payload using HMAC-SHA256
 */
export function signMandate(mandatePayload, secret = DEFAULT_SECRET_KEY) {
  const canonicalStr = canonicalize(mandatePayload);
  const signature = crypto.createHmac('sha256', secret).update(canonicalStr).digest('hex');
  return signature;
}

/**
 * Verifies a mandate payload against a given signature
 */
export function verifyMandateSignature(mandatePayload, signature, secret = DEFAULT_SECRET_KEY) {
  if (!signature || typeof signature !== 'string') {
    return false;
  }
  try {
    const expectedSig = signMandate(mandatePayload, secret);
    // Constant time comparison to prevent timing side-channel attacks
    const sigBuffer = Buffer.from(signature, 'hex');
    const expectedBuffer = Buffer.from(expectedSig, 'hex');
    if (sigBuffer.length !== expectedBuffer.length) return false;
    return crypto.timingSafeEqual(sigBuffer, expectedBuffer);
  } catch (err) {
    return false;
  }
}

/**
 * Generates a unique Nonce / JTI (JSON Token Identifier)
 */
export function generateJti() {
  return 'jti_' + crypto.randomBytes(16).toString('hex');
}

/**
 * Generates a unique Mandate ID compliant with AP2 specification
 */
export function generateMandateId(prefix = 'mnd_ap2_') {
  return prefix + Date.now().toString(36) + '_' + crypto.randomBytes(6).toString('hex');
}

/**
 * Computes hash-chained audit node
 */
export function computeAuditNodeHash(previousHash, auditPayload) {
  const data = previousHash + ':' + canonicalize(auditPayload);
  return sha256(data);
}

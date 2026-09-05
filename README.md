# Mandate Sentinel 🛡️
### AI Risk Manager & Mandate Verification Gate for Agent-Initiated Payments on Razorpay

[![Track](https://img.shields.io/badge/Razorpay%20Buildathon-Track%2002%20AI%20Risk%20Manager-blue.svg)](https://razorpay.com/buildathon/)
[![Protocols](https://img.shields.io/badge/Protocols-Google%20AP2%20%7C%20NPCI%20UAP%20%7C%20MCP%202.0-00f0ff.svg)](https://cloud.google.com/blog/products/ai-machine-learning/announcing-agents-to-payments-ap2-protocol)
[![Tests](https://img.shields.io/badge/Tests-12%2F12%20Passed%20(100%25)-00f59b.svg)](tests/unit_tests.js)
[![Benchmark](https://img.shields.io/badge/Precision-100.0%25%20%7C%20Recall%2099.5%25-purple.svg)](src/eval_suite/run_cli_benchmark.js)

**Mandate Sentinel** is an inline verification and defense-in-depth gate sitting between autonomous AI agents (Claude, Cursor, Replit, MCP clients) and Razorpay payment execution APIs.

---

## 🚀 Key Features

1. **Layer 1: Deterministic Mandate Verifier (AP2 / NPCI UAP Specification)**:
   - Cryptographic validation (`HMAC-SHA256` / `ECDSA-secp256k1`) on canonicalized JSON mandates.
   - Enforces hard per-transaction ceilings, cumulative budget caps, time windows, and replay JTI nonces.
   - Merchant allowlists and MCC category filtering (e.g. Food Delivery `5812`, Groceries `5411` vs Crypto `6051`, Vouchers `5947`).

2. **Layer 2: ML & Statistical Anomaly Scorer**:
   - Velocity burst detection against card-testing bots ($60\text{s}$ & $5\text{m}$ sliding windows).
   - Statistical Amount Z-Score calculation against the agent's historical baseline.
   - Novel merchant drift & off-hours anomaly scoring.

3. **Layer 3: NLP Prompt-Injection & Intent Tamper Guard (CSA AP2 STRIDE)**:
   - Traps jailbreaks and instruction overrides (*"IGNORE PREVIOUS BUDGET"*).
   - Zero-width Unicode obfuscation detector (`\u200B`--`\u200D`, `\uFEFF`).
   - Traps high-risk exfiltration targets (Apple Gift Cards, Binance USDT, Steam vouchers).
   - Semantic divergence analyzer between declared user mandate intent and cart line items.

4. **Verifiable Immutable Audit Ledger**:
   - SHA-256 hash-chained block trail linking every decision to Razorpay Order IDs (`order_xxx`).

5. **Track 02 Honest Metrics & Financial Cost Model**:
   - 1,000 synthetic transactions across 6 labeled classes.
   - **Precision: 100.0%**, **Recall: 99.5%**, **False Positive Rate: 0.0%**, **Throughput: 19,230 tx/sec**.
   - Net Economic Value Saved: **₹6,92,660.00**.

---

## ⚡ Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Run unit & protocol tests (12/12 passing)
npm test

# 3. Run the 1,000-sample adversarial benchmark
npm run benchmark

# 4. Launch the live interactive cyber-fintech dashboard
npm start
# Open http://localhost:3000 in your browser
```

---

## 📖 In-Depth Whitepaper
For full mathematical formulations, protocol mappings, and threat models, see **[`PROJECT_DOCUMENTATION.md`](file:///d:/Coding/My%20Projects/Razorpay/PROJECT_DOCUMENTATION.md)**.

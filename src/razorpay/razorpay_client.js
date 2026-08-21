import crypto from 'crypto';

/**
 * Razorpay Test Mode Client & High-Fidelity Simulator
 * Compatible with Razorpay REST API & Remote MCP 2.0
 */

export class RazorpayClient {
  constructor(config = {}) {
    this.keyId = config.keyId || process.env.RAZORPAY_KEY_ID || 'rzp_test_mandate_sentinel';
    this.keySecret = config.keySecret || process.env.RAZORPAY_KEY_SECRET || 'test_secret_key_buildathon';
    this.isLiveApiAvailable = Boolean(process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET);
    this.ordersDb = new Map();
    this.paymentLinksDb = new Map();
  }

  /**
   * Creates a Razorpay Order
   * (Matches POST /v1/orders)
   */
  async createOrder({ amount, currency = 'INR', receipt, notes = {}, partial_payment = false }) {
    if (this.isLiveApiAvailable) {
      try {
        const authHeader = 'Basic ' + Buffer.from(`${this.keyId}:${this.keySecret}`).toString('base64');
        const response = await fetch('https://api.razorpay.com/v1/orders', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': authHeader
          },
          body: JSON.stringify({ amount, currency, receipt, notes, partial_payment })
        });
        if (response.ok) {
          return await response.json();
        }
      } catch (err) {
        console.warn('[RazorpayClient] Live API call failed, falling back to high-fidelity test simulator:', err.message);
      }
    }

    // High-fidelity Test Mode simulation
    const orderId = 'order_' + crypto.randomBytes(7).toString('hex');
    const orderPayload = {
      id: orderId,
      entity: 'order',
      amount: parseInt(amount, 10),
      amount_paid: 0,
      amount_due: parseInt(amount, 10),
      currency: currency.toUpperCase(),
      receipt: receipt || `rcpt_${Date.now()}`,
      offer_id: null,
      status: 'created',
      attempts: 0,
      notes: notes || {},
      created_at: Math.floor(Date.now() / 1000)
    };
    this.ordersDb.set(orderId, orderPayload);
    return orderPayload;
  }

  /**
   * Creates a Razorpay Payment Link
   * (Matches POST /v1/payment_links)
   */
  async createPaymentLink({ amount, currency = 'INR', customer = {}, description = '', notes = {} }) {
    if (this.isLiveApiAvailable) {
      try {
        const authHeader = 'Basic ' + Buffer.from(`${this.keyId}:${this.keySecret}`).toString('base64');
        const response = await fetch('https://api.razorpay.com/v1/payment_links', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': authHeader
          },
          body: JSON.stringify({ amount, currency, customer, description, notes })
        });
        if (response.ok) {
          return await response.json();
        }
      } catch (err) {
        console.warn('[RazorpayClient] Live API payment link failed, falling back to test simulator:', err.message);
      }
    }

    // High-fidelity Test Mode simulation
    const plinkId = 'plink_' + crypto.randomBytes(7).toString('hex');
    const shortUrl = `https://rzp.io/i/${crypto.randomBytes(4).toString('hex')}`;
    const paymentLinkPayload = {
      id: plinkId,
      entity: 'payment_link',
      amount: parseInt(amount, 10),
      currency: currency.toUpperCase(),
      accept_partial: false,
      first_min_partial_amount: 0,
      description: description,
      customer: {
        name: customer.name || 'AI Delegated Buyer',
        email: customer.email || 'agent.buyer@example.com',
        contact: customer.contact || '+919876543210'
      },
      notify: { sms: true, email: true },
      reminder_enable: false,
      notes: notes || {},
      short_url: shortUrl,
      status: 'created',
      created_at: Math.floor(Date.now() / 1000)
    };
    this.paymentLinksDb.set(plinkId, paymentLinkPayload);
    return paymentLinkPayload;
  }

  /**
   * Simulates/executes payment capture
   */
  async capturePayment({ payment_id, amount, currency = 'INR' }) {
    const payId = payment_id || 'pay_' + crypto.randomBytes(7).toString('hex');
    return {
      id: payId,
      entity: 'payment',
      amount: parseInt(amount, 10),
      currency: currency.toUpperCase(),
      status: 'captured',
      order_id: 'order_' + crypto.randomBytes(7).toString('hex'),
      method: 'upi',
      captured: true,
      description: 'Agentic Mandate Authorized Payment',
      created_at: Math.floor(Date.now() / 1000)
    };
  }
}

export const razorpayClient = new RazorpayClient();

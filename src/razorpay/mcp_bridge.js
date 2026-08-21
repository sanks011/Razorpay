/**
 * Remote MCP 2.0 Bridge for Razorpay Agentic Payments
 * Defines tool signatures exposed to AI Agents and bridges tool calls into Mandate Sentinel.
 */

export const MCP_TOOLS_DEFINITIONS = [
  {
    name: 'razorpay_create_order',
    description: 'Creates a Razorpay Order to initiate an authorized agent payment. Requires AP2 mandate token.',
    inputSchema: {
      type: 'object',
      properties: {
        amount_paise: { type: 'integer', description: 'Amount in INR Paise (e.g. 50000 for ₹500.00)' },
        currency: { type: 'string', default: 'INR' },
        receipt: { type: 'string', description: 'Internal receipt identifier' },
        notes: { type: 'object', description: 'Key-value metadata for the order' },
        mandate_id: { type: 'string', description: 'AP2 / UAP authorized mandate ID' },
        mandate_signature: { type: 'string', description: 'Cryptographic signature of the mandate' },
        merchant_id: { type: 'string', description: 'Target merchant ID' },
        mcc_category: { type: 'string', description: 'Merchant Category Code (e.g. 5411 for Groceries)' },
        agent_reasoning: { type: 'string', description: 'Natural language explanation of why the agent is placing this order' }
      },
      required: ['amount_paise', 'mandate_id', 'merchant_id']
    }
  },
  {
    name: 'razorpay_create_payment_link',
    description: 'Generates a bounded Razorpay Payment Link for user checkout or delegated settlement.',
    inputSchema: {
      type: 'object',
      properties: {
        amount_paise: { type: 'integer', description: 'Amount in paise' },
        description: { type: 'string', description: 'Description of items/services' },
        mandate_id: { type: 'string', description: 'AP2 mandate ID' },
        customer: {
          type: 'object',
          properties: {
            name: { type: 'string' },
            email: { type: 'string' },
            contact: { type: 'string' }
          }
        }
      },
      required: ['amount_paise', 'mandate_id', 'description']
    }
  }
];

export function getMcpToolsList() {
  return {
    protocol_version: '2024-11-05',
    server_info: {
      name: 'razorpay-mandate-sentinel-mcp',
      version: '1.0.0',
      description: 'Razorpay Remote MCP Server with Mandate Sentinel Security Guard'
    },
    tools: MCP_TOOLS_DEFINITIONS
  };
}

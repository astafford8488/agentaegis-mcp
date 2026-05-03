import { TOOL_PRICING } from "../types/mcp.js";

export interface PaymentVerification {
  valid: boolean;
  tool_name: string;
  price_usd: number;
  payment_hash?: string;
  error?: string;
}

export function getToolPrice(toolName: string): number {
  return TOOL_PRICING[toolName] || 0;
}

export async function verifyPayment(
  toolName: string,
  paymentHeader?: string
): Promise<PaymentVerification> {
  const price = getToolPrice(toolName);

  // Phase 1: Payment verification is stubbed
  // In production, this validates the x402 payment header
  if (process.env.NODE_ENV === "development" || !process.env.X402_FACILITATOR_URL) {
    return {
      valid: true,
      tool_name: toolName,
      price_usd: price,
      payment_hash: "dev-mode-no-payment-required",
    };
  }

  if (!paymentHeader) {
    return {
      valid: false,
      tool_name: toolName,
      price_usd: price,
      error: `Payment required: $${price.toFixed(2)} USD. Include x402 payment header.`,
    };
  }

  // TODO: Validate payment with x402 facilitator
  // const facilitatorUrl = process.env.X402_FACILITATOR_URL;
  // const payeeAddress = process.env.X402_PAYEE_ADDRESS;
  // Verify payment amount >= price, payment is to payeeAddress, payment is not already spent

  return {
    valid: true,
    tool_name: toolName,
    price_usd: price,
    payment_hash: paymentHeader,
  };
}

export function generatePriceList(): Record<string, string> {
  const priceList: Record<string, string> = {};
  for (const [tool, price] of Object.entries(TOOL_PRICING)) {
    priceList[tool] = `$${price.toFixed(2)}`;
  }
  return priceList;
}

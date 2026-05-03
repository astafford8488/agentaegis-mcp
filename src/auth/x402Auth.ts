import type { Request, Response, NextFunction } from "express";
import { TOOL_PRICING } from "../types/mcp.js";
import { logUsage } from "../db/usageLog.js";
import { isDbConfigured } from "../db/client.js";

export interface PaymentRequirements {
  scheme: "exact";
  network: string;
  asset: string;
  payTo: string;
  maxAmountRequired: string;
  resource: string;
  description: string;
  mimeType: string;
  maxTimeoutSeconds: number;
}

const X402_FACILITATOR_URL = process.env.X402_FACILITATOR_URL || "https://x402.org/facilitator";
const X402_PAYEE_ADDRESS = process.env.X402_PAYEE_ADDRESS || "";
const X402_NETWORK = process.env.X402_NETWORK || "base-sepolia";
const X402_ASSET = process.env.X402_ASSET || "USDC";

const NETWORK_TO_USDC: Record<string, string> = {
  "base": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  "base-sepolia": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
  "ethereum": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
};

export function buildPaymentRequirements(toolName: string, resourcePath: string): PaymentRequirements {
  const priceUsd = TOOL_PRICING[toolName] || 0;
  const priceMicroUsd = Math.round(priceUsd * 1_000_000); // USDC has 6 decimals

  return {
    scheme: "exact",
    network: X402_NETWORK,
    asset: NETWORK_TO_USDC[X402_NETWORK] || X402_ASSET,
    payTo: X402_PAYEE_ADDRESS,
    maxAmountRequired: priceMicroUsd.toString(),
    resource: resourcePath,
    description: `AgentAegis ${toolName} — single tool invocation`,
    mimeType: "application/json",
    maxTimeoutSeconds: 60,
  };
}

interface VerifyResponse {
  isValid: boolean;
  payerAddress?: string;
  invalidReason?: string;
}

export async function verifyX402Payment(
  paymentHeader: string,
  requirements: PaymentRequirements
): Promise<VerifyResponse> {
  try {
    const response = await fetch(`${X402_FACILITATOR_URL}/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        paymentPayload: paymentHeader,
        paymentRequirements: requirements,
      }),
    });

    if (!response.ok) {
      return { isValid: false, invalidReason: `Facilitator returned ${response.status}` };
    }

    const result = await response.json();
    return {
      isValid: !!result.isValid,
      payerAddress: result.payer,
      invalidReason: result.invalidReason,
    };
  } catch (err) {
    return { isValid: false, invalidReason: `Verify failed: ${err}` };
  }
}

export async function settleX402Payment(
  paymentHeader: string,
  requirements: PaymentRequirements
): Promise<{ success: boolean; txHash?: string; error?: string }> {
  try {
    const response = await fetch(`${X402_FACILITATOR_URL}/settle`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        paymentPayload: paymentHeader,
        paymentRequirements: requirements,
      }),
    });

    if (!response.ok) {
      return { success: false, error: `Settle returned ${response.status}` };
    }

    const result = await response.json();
    return { success: !!result.success, txHash: result.transaction };
  } catch (err) {
    return { success: false, error: String(err) };
  }
}

export function require402Payment(toolName: string, resource: string, res: Response): void {
  const requirements = buildPaymentRequirements(toolName, resource);
  res.status(402).json({
    x402Version: 1,
    error: "X-PAYMENT header is required",
    accepts: [requirements],
  });
}

export async function processX402Payment(
  req: Request,
  res: Response,
  toolName: string,
  context: { target?: string; ip?: string; ua?: string }
): Promise<{ ok: true } | { ok: false }> {
  const paymentHeader = req.headers["x-payment"] as string | undefined;
  const requirements = buildPaymentRequirements(toolName, req.originalUrl);

  if (!paymentHeader) {
    require402Payment(toolName, req.originalUrl, res);
    return { ok: false };
  }

  const verification = await verifyX402Payment(paymentHeader, requirements);
  if (!verification.isValid) {
    res.status(402).json({
      x402Version: 1,
      error: `Payment invalid: ${verification.invalidReason || "Unknown"}`,
      accepts: [requirements],
    });
    return { ok: false };
  }

  const settlement = await settleX402Payment(paymentHeader, requirements);
  if (!settlement.success) {
    res.status(402).json({
      x402Version: 1,
      error: `Settlement failed: ${settlement.error || "Unknown"}`,
      accepts: [requirements],
    });
    return { ok: false };
  }

  // Set settlement response header
  res.setHeader(
    "X-PAYMENT-RESPONSE",
    Buffer.from(JSON.stringify({ success: true, transaction: settlement.txHash, network: X402_NETWORK })).toString("base64")
  );

  if (isDbConfigured()) {
    await logUsage({
      tool_name: toolName,
      target: context.target,
      price_usd: TOOL_PRICING[toolName],
      paid_via: "x402",
      payment_ref: settlement.txHash,
      success: true,
      request_ip: context.ip,
      user_agent: context.ua,
    });
  }

  return { ok: true };
}

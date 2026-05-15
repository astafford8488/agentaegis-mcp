import type { Request, Response, NextFunction } from "express";
import { TOOL_PRICING } from "../types/mcp.js";
import { logUsage } from "../db/usageLog.js";
import { isDbConfigured } from "../db/client.js";
import {
  isCdpMode,
  buildCdpChallenge,
  buildCdpPaymentRequirements,
  cdpVerify,
  cdpSettle,
} from "./x402Cdp.js";

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
  /** Required by the x402 facilitator for EIP-712 signature verification.
   *  Identifies the USDC contract's typed-data domain so the signed payload
   *  can be reconstructed and verified. */
  extra?: {
    name: string;
    version: string;
  };
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

// EIP-712 domain for USDC's transferWithAuthorization. Same on testnet/mainnet.
// Circle's USDC uses {name: "USDC", version: "2"} in the typed data domain.
const USDC_EIP712_DOMAIN = { name: "USDC", version: "2" };

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
    extra: USDC_EIP712_DOMAIN,
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
    const paymentPayload = decodePaymentHeader(paymentHeader);
    const response = await fetch(`${X402_FACILITATOR_URL}/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        paymentPayload,
        paymentRequirements: requirements,
      }),
    });

    const text = await response.text();
    if (!response.ok) {
      console.error("[x402] verify failed:", response.status, text.slice(0, 500));
      return { isValid: false, invalidReason: `Facilitator ${response.status}: ${text.slice(0, 200)}` };
    }

    const result = JSON.parse(text);
    return {
      isValid: !!result.isValid,
      payerAddress: result.payer,
      invalidReason: result.invalidReason || result.invalidMessage,
    };
  } catch (err) {
    return { isValid: false, invalidReason: `Verify failed: ${err}` };
  }
}

function decodePaymentHeader(header: string): unknown {
  // x402-fetch sets X-PAYMENT to base64(JSON(payload)). The facilitator
  // expects the DECODED object, not the base64 string.
  try {
    return JSON.parse(Buffer.from(header, "base64").toString("utf-8"));
  } catch {
    try { return JSON.parse(header); } catch { return header; }
  }
}

export async function settleX402Payment(
  paymentHeader: string,
  requirements: PaymentRequirements
): Promise<{ success: boolean; txHash?: string; error?: string }> {
  try {
    const paymentPayload = decodePaymentHeader(paymentHeader);
    const response = await fetch(`${X402_FACILITATOR_URL}/settle`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        paymentPayload,
        paymentRequirements: requirements,
      }),
    });

    const text = await response.text();
    if (!response.ok) {
      console.error("[x402] settle failed:", response.status, text.slice(0, 500));
      return { success: false, error: `Settle ${response.status}: ${text.slice(0, 200)}` };
    }

    const result = JSON.parse(text);
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

/**
 * Build a fully-qualified resource URL from the Express request. Both the
 * legacy x402.org facilitator and the CDP facilitator require the resource
 * field to be a full URL with scheme + host + path (the reference x402-fetch
 * client zod-rejects path-only values before signing).
 */
function fullResourceUrl(req: Request): string {
  const proto = (req.headers["x-forwarded-proto"] as string | undefined) || req.protocol || "https";
  const host = req.headers["host"] || "agentaegis-mcp-production.up.railway.app";
  return `${proto}://${host}${req.originalUrl}`;
}

/**
 * CDP-mode payment processor. Mirrors processX402Payment's flow but uses
 * v2 wire format and the SDK's HTTPFacilitatorClient. Isolated so the
 * legacy raw-fetch path stays untouched for testnet / self-hosted
 * facilitators.
 */
async function processCdpPayment(
  req: Request,
  res: Response,
  toolName: string,
  paymentHeader: string | undefined,
  context: { target?: string; ip?: string; ua?: string }
): Promise<{ ok: true } | { ok: false }> {
  const requirements = buildCdpPaymentRequirements(toolName);
  const resourceUrl = fullResourceUrl(req);

  if (!paymentHeader) {
    res.status(402).json(buildCdpChallenge(toolName, resourceUrl));
    return { ok: false };
  }

  const paymentPayload = decodePaymentHeader(paymentHeader);

  const verification = await cdpVerify(paymentPayload, requirements);
  if (!verification.isValid) {
    res.status(402).json({
      ...buildCdpChallenge(toolName, resourceUrl),
      error: `Payment invalid: ${verification.invalidReason || "Unknown"}`,
    });
    return { ok: false };
  }

  const settlement = await cdpSettle(paymentPayload, requirements);
  if (!settlement.success) {
    res.status(402).json({
      ...buildCdpChallenge(toolName, resourceUrl),
      error: `Settlement failed: ${settlement.error || "Unknown"}`,
    });
    return { ok: false };
  }

  res.setHeader(
    "X-PAYMENT-RESPONSE",
    Buffer.from(
      JSON.stringify({
        success: true,
        transaction: settlement.txHash,
        network: settlement.network || requirements.network,
      })
    ).toString("base64")
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

export async function processX402Payment(
  req: Request,
  res: Response,
  toolName: string,
  context: { target?: string; ip?: string; ua?: string }
): Promise<{ ok: true } | { ok: false }> {
  const paymentHeader = req.headers["x-payment"] as string | undefined;

  // CDP-mode branch: SDK-based verify/settle, x402 v2 wire format. The legacy
  // raw-fetch path below is unchanged and is used whenever CDP credentials
  // are absent (testnet, self-hosted facilitators, or any future provider).
  if (isCdpMode()) {
    return processCdpPayment(req, res, toolName, paymentHeader, context);
  }

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

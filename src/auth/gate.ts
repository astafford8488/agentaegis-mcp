import type { Request, Response } from "express";
import type { AuthenticatedRequest } from "./apiKeyAuth.js";
import { chargeApiKey } from "./apiKeyAuth.js";
import { processX402Payment } from "./x402Auth.js";
import { TOOL_PRICING } from "../types/mcp.js";
import { isDbConfigured } from "../db/client.js";

export interface PaymentResult {
  authorized: boolean;
  payment_method?: "api_key" | "x402" | "free_tier";
  payment_ref?: string;
  reason?: string;
}

/**
 * Authenticate and authorize a tool call.
 * Order of precedence:
 *  1. If API key present and has budget → charge against API key
 *  2. If X-PAYMENT header present → validate x402 payment
 *  3. If neither → return 402 Payment Required (with x402 requirements)
 */
export async function authorizeToolCall(
  req: AuthenticatedRequest,
  res: Response,
  toolName: string,
  target?: string
): Promise<PaymentResult> {
  const priceUsd = TOOL_PRICING[toolName] || 0;
  const ip = req.ip;
  const ua = req.headers["user-agent"];

  // Free in dev mode
  if (process.env.NODE_ENV === "development" && process.env.SKIP_PAYMENT === "true") {
    return { authorized: true, payment_method: "free_tier", payment_ref: "dev-mode" };
  }

  // Path 1: API key
  if (req.apiKey && isDbConfigured()) {
    const result = await chargeApiKey(req.apiKey, toolName, priceUsd, {
      target, success: true, ip, ua,
    });
    if (result.ok) {
      return { authorized: true, payment_method: "api_key", payment_ref: req.apiKey.id };
    }
    return { authorized: false, reason: result.reason };
  }

  // Path 2: x402 payment
  const x402Result = await processX402Payment(req, res, toolName, { target, ip, ua });
  if (x402Result.ok) {
    return { authorized: true, payment_method: "x402" };
  }

  // x402 already wrote the 402 response
  return { authorized: false, reason: "Payment required" };
}

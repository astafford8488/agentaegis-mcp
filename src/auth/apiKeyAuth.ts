import type { Request, Response, NextFunction } from "express";
import { findApiKeyByRawKey, recordApiKeyUsage, checkApiKeyBudget } from "../db/apiKeys.js";
import { logUsage } from "../db/usageLog.js";
import { isDbConfigured } from "../db/client.js";
import type { APIKey } from "../db/types.js";

export interface AuthenticatedRequest extends Request {
  apiKey?: APIKey;
  authMethod?: "api_key" | "x402" | "none";
  paymentRef?: string;
  toolPrice?: number;
}

export async function apiKeyAuth(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  const authHeader = req.headers["authorization"];
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    req.authMethod = "none";
    return next();
  }

  const rawKey = authHeader.slice(7);
  if (!rawKey.startsWith("aegis_")) {
    req.authMethod = "none";
    return next();
  }

  if (!isDbConfigured()) {
    return res.status(503).json({ error: "Database not configured" });
  }

  const apiKey = await findApiKeyByRawKey(rawKey);
  if (!apiKey) {
    return res.status(401).json({ error: "Invalid API key" });
  }

  req.apiKey = apiKey;
  req.authMethod = "api_key";
  next();
}

export async function chargeApiKey(
  apiKey: APIKey,
  toolName: string,
  priceUsd: number,
  context: { target?: string; success: boolean; error_message?: string; ip?: string; ua?: string }
): Promise<{ ok: boolean; reason?: string }> {
  const ok = await checkApiKeyBudget(apiKey, priceUsd);
  if (!ok) {
    return {
      ok: false,
      reason: `Monthly limit ($${apiKey.monthly_limit_usd}) would be exceeded. Current usage: $${apiKey.current_month_usage_usd.toFixed(4)}.`,
    };
  }

  if (context.success) {
    await recordApiKeyUsage(apiKey.id, priceUsd);
  }

  await logUsage({
    customer_id: apiKey.customer_id,
    api_key_id: apiKey.id,
    tool_name: toolName,
    target: context.target,
    price_usd: priceUsd,
    paid_via: "api_key_balance",
    success: context.success,
    error_message: context.error_message,
    request_ip: context.ip,
    user_agent: context.ua,
  });

  return { ok: true };
}

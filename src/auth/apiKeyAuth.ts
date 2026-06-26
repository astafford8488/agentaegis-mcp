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

/**
 * Pull a raw `aegis_` API key out of request headers, accepting three forms so
 * any client or gateway works:
 *   - `Authorization: Bearer aegis_...`  (canonical)
 *   - `Authorization: aegis_...`         (bare — e.g. the Smithery gateway forwarding a config value)
 *   - `X-API-Key: aegis_...`             (common alternative header)
 * Returns undefined when no aegis_ key is present (caller falls through to x402/free).
 * Pure + exported for unit testing.
 */
export function extractApiKey(headers: {
  authorization?: string | string[];
  "x-api-key"?: string | string[];
}): string | undefined {
  const auth = Array.isArray(headers.authorization) ? headers.authorization[0] : headers.authorization;
  const xak = Array.isArray(headers["x-api-key"]) ? headers["x-api-key"][0] : headers["x-api-key"];
  let rawKey: string | undefined;
  if (auth && auth.trim()) {
    const m = auth.match(/^Bearer\s+(.+)$/i); // tolerate any casing of "Bearer"
    rawKey = (m ? m[1] : auth).trim();
  } else if (xak && xak.trim()) {
    rawKey = xak.trim();
  }
  return rawKey && rawKey.startsWith("aegis_") ? rawKey : undefined;
}

export async function apiKeyAuth(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  const rawKey = extractApiKey(req.headers);
  if (!rawKey) {
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
  context: { target?: string; success: boolean; error_message?: string; ip?: string; ua?: string; agentId?: string }
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
    agent_id: context.agentId,
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

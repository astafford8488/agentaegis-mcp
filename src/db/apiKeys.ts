import * as crypto from "crypto";
import { getDb } from "./client.js";
import type { APIKey } from "./types.js";

const KEY_PREFIX = "aegis_";

export function generateApiKey(): { key: string; hash: string; prefix: string } {
  const random = crypto.randomBytes(32).toString("base64url");
  const key = `${KEY_PREFIX}${random}`;
  const hash = crypto.createHash("sha256").update(key).digest("hex");
  const prefix = key.slice(0, 12);
  return { key, hash, prefix };
}

export function hashApiKey(key: string): string {
  return crypto.createHash("sha256").update(key).digest("hex");
}

export async function createApiKey(input: {
  customer_id: string;
  name: string;
  monthly_limit_usd?: number;
}): Promise<{ apiKey: APIKey; rawKey: string }> {
  const { key, hash, prefix } = generateApiKey();

  const { data, error } = await getDb()
    .from("aegis_api_keys")
    .insert({
      customer_id: input.customer_id,
      key_hash: hash,
      key_prefix: prefix,
      name: input.name,
      monthly_limit_usd: input.monthly_limit_usd || 100,
    })
    .select()
    .single();

  if (error) throw error;
  return { apiKey: data, rawKey: key };
}

export async function findApiKeyByRawKey(rawKey: string): Promise<APIKey | null> {
  const hash = hashApiKey(rawKey);

  const { data, error } = await getDb()
    .from("aegis_api_keys")
    .select("*")
    .eq("key_hash", hash)
    .is("revoked_at", null)
    .maybeSingle();

  if (error) return null;
  return data;
}

export async function recordApiKeyUsage(apiKeyId: string, amountUsd: number): Promise<void> {
  const { data: key } = await getDb()
    .from("aegis_api_keys")
    .select("current_month_usage_usd")
    .eq("id", apiKeyId)
    .single();

  if (!key) return;

  await getDb()
    .from("aegis_api_keys")
    .update({
      current_month_usage_usd: key.current_month_usage_usd + amountUsd,
      last_used_at: new Date().toISOString(),
    })
    .eq("id", apiKeyId);
}

export async function checkApiKeyBudget(apiKey: APIKey, amountUsd: number): Promise<boolean> {
  return apiKey.current_month_usage_usd + amountUsd <= apiKey.monthly_limit_usd;
}

export async function revokeApiKey(apiKeyId: string): Promise<void> {
  await getDb()
    .from("aegis_api_keys")
    .update({ revoked_at: new Date().toISOString() })
    .eq("id", apiKeyId);
}

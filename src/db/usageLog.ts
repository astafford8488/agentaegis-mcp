import { getDb } from "./client.js";
import type { UsageLogEntry } from "./types.js";

export async function logUsage(input: {
  customer_id?: string;
  api_key_id?: string;
  tool_name: string;
  target?: string;
  price_usd: number;
  paid_via: UsageLogEntry["paid_via"];
  payment_ref?: string;
  success: boolean;
  error_message?: string;
  request_ip?: string;
  user_agent?: string;
}): Promise<void> {
  await getDb().from("aegis_usage_log").insert({
    customer_id: input.customer_id || null,
    api_key_id: input.api_key_id || null,
    tool_name: input.tool_name,
    target: input.target || null,
    price_usd: input.price_usd,
    paid_via: input.paid_via,
    payment_ref: input.payment_ref || null,
    success: input.success,
    error_message: input.error_message || null,
    request_ip: input.request_ip || null,
    user_agent: input.user_agent || null,
  });
}

export async function getCustomerUsage(
  customerId: string,
  fromDate?: string
): Promise<{ total_calls: number; total_spend_usd: number; by_tool: Record<string, number> }> {
  let query = getDb().from("aegis_usage_log").select("tool_name, price_usd").eq("customer_id", customerId).eq("success", true);

  if (fromDate) {
    query = query.gte("created_at", fromDate);
  }

  const { data, error } = await query;
  if (error) throw error;

  const byTool: Record<string, number> = {};
  let totalSpend = 0;
  for (const entry of data || []) {
    byTool[entry.tool_name] = (byTool[entry.tool_name] || 0) + 1;
    totalSpend += parseFloat(entry.price_usd as any);
  }

  return {
    total_calls: data?.length || 0,
    total_spend_usd: Math.round(totalSpend * 10000) / 10000,
    by_tool: byTool,
  };
}

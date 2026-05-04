// account_balance — agent-facing tool that returns the calling customer's
// current balance, monthly budget consumption, and affordability hints.
//
// This is FREE for the agent to call (price_usd: 0). It exists so an
// autonomous agent can check whether it can afford its next tool call
// without paying to find out.
//
// Resolution: when the HTTP transport authenticates a request with an API key,
// we attach the api_key + customer to the AsyncLocalStorage context. This tool
// reads that context. When called via stdio (Claude Desktop in dev mode),
// returns a "no account" response.

import { z } from "zod";
import { TOOL_PRICING } from "../../types/mcp.js";
import { getDb, isDbConfigured } from "../../db/client.js";
import { getCustomerUsage } from "../../db/usageLog.js";
import { getRequestContext } from "../../auth/requestContext.js";

export const accountBalanceSchema = z.object({});

export type AccountBalanceInput = z.infer<typeof accountBalanceSchema>;

export async function accountBalance(_input: AccountBalanceInput) {
  const ctx = getRequestContext();

  if (!ctx?.apiKey || !isDbConfigured()) {
    return {
      authenticated: false,
      message: "No API key context. This tool returns balance for the API key making the request — call it through the HTTP transport with Bearer auth.",
    };
  }

  const apiKey = ctx.apiKey;

  const { data: customer, error } = await getDb()
    .from("aegis_customers")
    .select("id, email, prepaid_balance_usd")
    .eq("id", apiKey.customer_id)
    .maybeSingle();

  if (error || !customer) {
    return { authenticated: true, error: "Customer record not found" };
  }

  const monthStart = new Date();
  monthStart.setUTCDate(1);
  monthStart.setUTCHours(0, 0, 0, 0);
  const monthUsage = await getCustomerUsage(customer.id, monthStart.toISOString());

  const balance = parseFloat(customer.prepaid_balance_usd as any);
  const monthlyLimit = parseFloat(apiKey.monthly_limit_usd as any);
  const monthlyUsage = parseFloat(apiKey.current_month_usage_usd as any);

  const paidPrices = Object.values(TOOL_PRICING).filter((p) => p > 0);
  const cheapestTool = paidPrices.length > 0 ? Math.min(...paidPrices) : 0;
  const tools_affordable = Object.entries(TOOL_PRICING)
    .filter(([, price]) => price > 0)
    .map(([name, price]) => ({ name, price_usd: price, calls_remaining: balance > 0 ? Math.floor(balance / price) : 0 }))
    .sort((a, b) => a.price_usd - b.price_usd);

  return {
    authenticated: true,
    customer_id: customer.id,
    email: customer.email,
    prepaid_balance_usd: balance,
    monthly_limit_usd: monthlyLimit,
    monthly_usage_usd: monthlyUsage,
    monthly_remaining_usd: Math.max(0, monthlyLimit - monthlyUsage),
    usage_this_month: monthUsage,
    affordability: {
      cheapest_tool_price_usd: cheapestTool,
      cheapest_tool_calls_remaining: balance > 0 ? Math.floor(balance / cheapestTool) : 0,
      balance_low_warning: balance < 1.0,
      tools_affordable,
    },
    topup_url: `/v1/customers/${customer.id}/checkout-session`,
  };
}

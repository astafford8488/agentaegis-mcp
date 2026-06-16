// Admin routes — auth-gated dashboard for the operator.
//
// Auth model: a single shared admin token (ADMIN_TOKEN env var). Sent
// as Authorization: Bearer <token> OR ?token=<token> query param.
// This is intentionally lightweight — Phase 3 admin is for Andrew only.
// Multi-admin / OAuth comes in a later phase if needed.

import express, { type Router, type Request, type Response, type NextFunction } from "express";
import * as path from "path";
import * as crypto from "crypto";
import { fileURLToPath } from "url";
import { getDb, isDbConfigured } from "../db/client.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function checkAdminAuth(req: Request, res: Response, next: NextFunction) {
  const expected = process.env.ADMIN_TOKEN;
  if (!expected) {
    return res.status(503).json({ error: "Admin disabled (ADMIN_TOKEN not set)" });
  }

  const headerToken = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  const queryToken = (req.query.token as string) || "";
  const provided = headerToken || queryToken;

  if (!provided) return res.status(401).json({ error: "Admin token required" });

  // Constant-time comparison
  const a = Buffer.from(provided);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(403).json({ error: "Invalid admin token" });
  }

  next();
}

export function buildAdminRouter(): Router {
  const router = express.Router();

  // Static dashboard — gated by ?token=...
  router.get("/", checkAdminAuth, (_req: Request, res: Response) => {
    res.sendFile(path.join(__dirname, "..", "..", "public", "admin", "index.html"));
  });

  // Bazaar listing check — queries the CDP Bazaar discovery index for our
  // resources (by payTo) + a keyword search. Uses the server's CDP creds
  // (CDP_API_KEY_ID/SECRET), which the local machine doesn't have, so this is
  // the only place we can verify the listing. Admin-token gated.
  router.get("/bazaar-check", checkAdminAuth, async (_req: Request, res: Response) => {
    try {
      const { facilitator } = await import("@coinbase/x402");
      const { HTTPFacilitatorClient } = await import("@x402/core/server");
      const { withBazaar } = await import("@x402/extensions/bazaar");
      // Cast through `never`: @x402/extensions resolves @x402/core@2.15.0 while
      // we use 2.12.0 — structurally identical clients, but TS sees a private-field
      // nominal mismatch. Runtime is fine (both expose createAuthHeaders + url).
      const client = withBazaar(new HTTPFacilitatorClient(facilitator) as never) as unknown as {
        extensions: { bazaar: { listResources: (p: Record<string, unknown>) => Promise<unknown>; search: (p: Record<string, unknown>) => Promise<unknown> } };
      };
      const payTo = process.env.X402_PAYEE_ADDRESS || "";
      const [byPayTo, bySearch] = await Promise.all([
        client.extensions.bazaar.listResources({ payTo, limit: 50 }).catch((e: unknown) => ({ error: String(e) })),
        client.extensions.bazaar.search({ query: "AgentAegis cybersecurity scan", limit: 20 }).catch((e: unknown) => ({ error: String(e) })),
      ]);
      res.json({ payTo, network: process.env.X402_NETWORK, cdp_mode: Boolean(process.env.CDP_API_KEY_ID && process.env.CDP_API_KEY_SECRET), listed_by_payTo: byPayTo, search_results: bySearch });
    } catch (e: unknown) {
      res.status(500).json({ error: String(e) });
    }
  });

  // === Stats endpoints ===

  // Overview: customer count, total spend, total calls
  router.get("/stats/overview", checkAdminAuth, async (_req: Request, res: Response) => {
    if (!isDbConfigured()) return res.status(503).json({ error: "DB not configured" });

    try {
      const since30d = new Date(Date.now() - 30 * 86400000).toISOString();

      const [customers, apiKeys, usage30d, jobs30d, balances] = await Promise.all([
        getDb().from("aegis_customers").select("id", { count: "exact", head: true }),
        getDb().from("aegis_api_keys").select("id", { count: "exact", head: true }).is("revoked_at", null),
        getDb().from("aegis_usage_log").select("price_usd, paid_via, success").gte("created_at", since30d),
        getDb().from("aegis_scan_jobs").select("status").gte("created_at", since30d),
        getDb().from("aegis_customers").select("prepaid_balance_usd"),
      ]);

      const usage = usage30d.data || [];
      const successCount = usage.filter((u: any) => u.success && u.price_usd > 0).length;
      const totalRevenue30d = usage
        .filter((u: any) => u.success && u.price_usd > 0)
        .reduce((acc: number, u: any) => acc + parseFloat(u.price_usd), 0);
      const totalCredits30d = usage
        .filter((u: any) => u.paid_via === "stripe")
        .reduce((acc: number, u: any) => acc + Math.abs(parseFloat(u.price_usd)), 0);

      const jobs = jobs30d.data || [];
      const totalBalance = (balances.data || []).reduce(
        (acc: number, c: any) => acc + parseFloat(c.prepaid_balance_usd || "0"),
        0
      );

      res.json({
        customer_count: customers.count || 0,
        active_api_keys: apiKeys.count || 0,
        prepaid_balance_total_usd: Math.round(totalBalance * 100) / 100,
        last_30_days: {
          tool_calls_succeeded: successCount,
          revenue_usd: Math.round(totalRevenue30d * 100) / 100,
          credits_purchased_usd: Math.round(totalCredits30d * 100) / 100,
          jobs_total: jobs.length,
          jobs_completed: jobs.filter((j: any) => j.status === "completed").length,
          jobs_failed: jobs.filter((j: any) => j.status === "failed").length,
          jobs_running: jobs.filter((j: any) => j.status === "running").length,
        },
      });
    } catch (err) {
      res.status(500).json({ error: String(err) });
    }
  });

  // Top customers by 30-day spend
  router.get("/stats/customers", checkAdminAuth, async (_req: Request, res: Response) => {
    if (!isDbConfigured()) return res.status(503).json({ error: "DB not configured" });

    try {
      const since30d = new Date(Date.now() - 30 * 86400000).toISOString();
      const { data: usage } = await getDb()
        .from("aegis_usage_log")
        .select("customer_id, tool_name, price_usd, success")
        .gte("created_at", since30d)
        .eq("success", true);

      const byCustomer = new Map<string, { spend: number; calls: number; tools: Set<string> }>();
      for (const u of usage || []) {
        if (!u.customer_id) continue;
        const price = parseFloat(u.price_usd as any);
        if (price <= 0) continue; // skip credits
        const entry = byCustomer.get(u.customer_id) || { spend: 0, calls: 0, tools: new Set() };
        entry.spend += price;
        entry.calls += 1;
        entry.tools.add(u.tool_name);
        byCustomer.set(u.customer_id, entry);
      }

      const topIds = Array.from(byCustomer.entries())
        .sort((a, b) => b[1].spend - a[1].spend)
        .slice(0, 25);

      const { data: customers } = await getDb()
        .from("aegis_customers")
        .select("id, email, company, prepaid_balance_usd, created_at")
        .in("id", topIds.map((t) => t[0]));

      const lookup = Object.fromEntries((customers || []).map((c: any) => [c.id, c]));

      res.json({
        top_customers: topIds.map(([id, stats]) => ({
          ...lookup[id],
          spend_30d_usd: Math.round(stats.spend * 100) / 100,
          calls_30d: stats.calls,
          tools_used: Array.from(stats.tools),
        })),
      });
    } catch (err) {
      res.status(500).json({ error: String(err) });
    }
  });

  // Top tools by 30-day usage
  router.get("/stats/tools", checkAdminAuth, async (_req: Request, res: Response) => {
    if (!isDbConfigured()) return res.status(503).json({ error: "DB not configured" });

    try {
      const since30d = new Date(Date.now() - 30 * 86400000).toISOString();
      const { data: usage } = await getDb()
        .from("aegis_usage_log")
        .select("tool_name, price_usd, success")
        .gte("created_at", since30d);

      const byTool = new Map<string, { calls: number; revenue: number; failures: number }>();
      for (const u of usage || []) {
        const entry = byTool.get(u.tool_name) || { calls: 0, revenue: 0, failures: 0 };
        if (u.success) {
          entry.calls += 1;
          if (u.price_usd > 0) entry.revenue += parseFloat(u.price_usd as any);
        } else {
          entry.failures += 1;
        }
        byTool.set(u.tool_name, entry);
      }

      const tools = Array.from(byTool.entries())
        .map(([name, stats]) => ({
          tool_name: name,
          calls: stats.calls,
          failures: stats.failures,
          revenue_usd: Math.round(stats.revenue * 100) / 100,
        }))
        .sort((a, b) => b.calls - a.calls);

      res.json({ tools });
    } catch (err) {
      res.status(500).json({ error: String(err) });
    }
  });

  // Recent errors (failed scan jobs OR usage_log entries with success=false)
  router.get("/stats/errors", checkAdminAuth, async (_req: Request, res: Response) => {
    if (!isDbConfigured()) return res.status(503).json({ error: "DB not configured" });

    try {
      const since7d = new Date(Date.now() - 7 * 86400000).toISOString();
      const [failedJobs, failedUsage] = await Promise.all([
        getDb()
          .from("aegis_scan_jobs")
          .select("id, customer_id, tool_name, target, error_message, created_at")
          .eq("status", "failed")
          .gte("created_at", since7d)
          .order("created_at", { ascending: false })
          .limit(50),
        getDb()
          .from("aegis_usage_log")
          .select("customer_id, tool_name, target, error_message, created_at")
          .eq("success", false)
          .gte("created_at", since7d)
          .order("created_at", { ascending: false })
          .limit(50),
      ]);

      res.json({
        failed_jobs: failedJobs.data || [],
        failed_calls: failedUsage.data || [],
      });
    } catch (err) {
      res.status(500).json({ error: String(err) });
    }
  });

  return router;
}

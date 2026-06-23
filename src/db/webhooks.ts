// Webhook management (customer-scoped CRUD). The delivery engine already exists
// (src/webhooks/dispatcher.ts); this is the missing surface so customers/agents
// can register + manage the webhooks that get delivered to. All reads/writes are
// scoped to customer_id so one customer can never touch another's webhooks.

import * as crypto from "crypto";
import { getDb } from "./client.js";
import type { Webhook } from "./types.js";
import { WEBHOOK_EVENTS } from "../webhooks/dispatcher.js";

const DEFAULT_EVENTS = ["scan.completed", "scan.failed"];

export async function createWebhook(input: {
  customer_id: string;
  url: string;
  events_subscribed?: string[];
}): Promise<Webhook> {
  // 48-hex signing secret. Returned to the caller exactly once; used by the
  // dispatcher to HMAC-sign every delivery (X-AgentAegis-Signature).
  const secret = "whsec_" + crypto.randomBytes(24).toString("hex");
  const events = input.events_subscribed?.length ? input.events_subscribed : DEFAULT_EVENTS;

  const { data, error } = await getDb()
    .from("aegis_webhooks")
    .insert({ customer_id: input.customer_id, url: input.url, secret, events_subscribed: events, active: true })
    .select()
    .single();
  if (error) throw error;
  return data as Webhook;
}

export async function listWebhooks(customerId: string): Promise<Webhook[]> {
  const { data, error } = await getDb()
    .from("aegis_webhooks")
    .select("*")
    .eq("customer_id", customerId)
    .order("created_at", { ascending: false });
  if (error) throw error;
  return (data || []) as Webhook[];
}

export async function getWebhook(customerId: string, webhookId: string): Promise<Webhook | null> {
  const { data } = await getDb()
    .from("aegis_webhooks")
    .select("*")
    .eq("customer_id", customerId)
    .eq("id", webhookId)
    .maybeSingle();
  return (data as Webhook) ?? null;
}

export async function updateWebhook(
  customerId: string,
  webhookId: string,
  patch: { url?: string; events_subscribed?: string[]; active?: boolean }
): Promise<Webhook | null> {
  const upd: Record<string, unknown> = {};
  if (patch.url !== undefined) upd.url = patch.url;
  if (patch.events_subscribed !== undefined) upd.events_subscribed = patch.events_subscribed;
  if (patch.active !== undefined) upd.active = patch.active;
  if (Object.keys(upd).length === 0) return getWebhook(customerId, webhookId);

  const { data, error } = await getDb()
    .from("aegis_webhooks")
    .update(upd)
    .eq("customer_id", customerId)
    .eq("id", webhookId)
    .select()
    .maybeSingle();
  if (error) throw error;
  return (data as Webhook) ?? null;
}

export async function deleteWebhook(customerId: string, webhookId: string): Promise<boolean> {
  const { data, error } = await getDb()
    .from("aegis_webhooks")
    .delete()
    .eq("customer_id", customerId)
    .eq("id", webhookId)
    .select("id");
  if (error) throw error;
  return Array.isArray(data) && data.length > 0;
}

/** Validate a customer-supplied webhook URL: public https only (no plaintext, no
 *  loopback/private hosts to avoid using the dispatcher as an SSRF probe). */
export function validateWebhookUrl(url: unknown): { ok: true; url: string } | { ok: false; reason: string } {
  if (typeof url !== "string" || !url) return { ok: false, reason: "url required" };
  let parsed: URL;
  try { parsed = new URL(url); } catch { return { ok: false, reason: "url is not a valid URL" }; }
  if (parsed.protocol !== "https:") return { ok: false, reason: "url must use https" };
  const h = parsed.hostname;
  if (/^(localhost$|127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|\[?::1\]?$|0\.)/.test(h) || !h.includes(".")) {
    return { ok: false, reason: "url must be a public host (no localhost/private addresses)" };
  }
  return { ok: true, url };
}

/** Validate an events array against the canonical WEBHOOK_EVENTS list. */
export function validateEvents(events: unknown): { ok: true; events?: string[] } | { ok: false; reason: string } {
  if (events === undefined) return { ok: true };
  if (!Array.isArray(events) || events.some((e) => typeof e !== "string" || !(WEBHOOK_EVENTS as readonly string[]).includes(e))) {
    return { ok: false, reason: `events must be a subset of: ${WEBHOOK_EVENTS.join(", ")}` };
  }
  return { ok: true, events: events as string[] };
}

/** Strip the signing secret from a webhook before returning it (only ever exposed
 *  once, at creation). Replaces it with a boolean so the client knows one is set. */
export function publicWebhook(w: Webhook): Omit<Webhook, "secret"> & { secret_set: boolean } {
  const { secret, ...rest } = w;
  return { ...rest, secret_set: Boolean(secret) };
}

export { WEBHOOK_EVENTS };

import * as crypto from "crypto";
import { getDb, isDbConfigured } from "../db/client.js";
import type { Webhook } from "../db/types.js";

export type WebhookEvent =
  | "scan.completed"
  | "scan.failed"
  | "scan.timeout"
  | "incident.triaged"
  | "compliance.assessed";

const MAX_ATTEMPTS = 5;
const RETRY_BACKOFF_MS = [60_000, 300_000, 900_000, 3_600_000, 14_400_000];

function signPayload(payload: string, secret: string): string {
  return crypto.createHmac("sha256", secret).update(payload).digest("hex");
}

export async function dispatchWebhook(
  customerId: string,
  eventType: WebhookEvent,
  payload: Record<string, unknown>
): Promise<void> {
  if (!isDbConfigured()) return;

  const { data: webhooks } = await getDb()
    .from("webhooks")
    .select("*")
    .eq("customer_id", customerId)
    .eq("active", true)
    .contains("events_subscribed", [eventType]);

  if (!webhooks?.length) return;

  for (const webhook of webhooks) {
    await deliverToWebhook(webhook as Webhook, eventType, payload);
  }
}

async function deliverToWebhook(
  webhook: Webhook,
  eventType: WebhookEvent,
  payload: Record<string, unknown>
): Promise<void> {
  const body = JSON.stringify({
    id: crypto.randomUUID(),
    event: eventType,
    created_at: new Date().toISOString(),
    data: payload,
  });

  const signature = signPayload(body, webhook.secret);

  const { data: delivery } = await getDb()
    .from("webhook_deliveries")
    .insert({
      webhook_id: webhook.id,
      event_type: eventType,
      payload: { body: JSON.parse(body) },
      attempts: 1,
    })
    .select()
    .single();

  try {
    const response = await fetch(webhook.url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-AgentAegis-Signature": `sha256=${signature}`,
        "X-AgentAegis-Event": eventType,
        "X-AgentAegis-Delivery": delivery?.id || "",
        "User-Agent": "AgentAegis-Webhook/1.0",
      },
      body,
      signal: AbortSignal.timeout(10_000),
    });

    const responseText = await response.text().catch(() => "");

    if (response.ok) {
      await getDb()
        .from("webhook_deliveries")
        .update({
          response_status: response.status,
          response_body: responseText.slice(0, 1000),
          delivered_at: new Date().toISOString(),
        })
        .eq("id", delivery?.id);

      await getDb()
        .from("webhooks")
        .update({
          last_delivery_at: new Date().toISOString(),
          last_delivery_status: response.status,
          failure_count: 0,
        })
        .eq("id", webhook.id);
    } else {
      await scheduleRetry(delivery?.id, webhook.id, 1, response.status, responseText);
    }
  } catch (err) {
    await scheduleRetry(delivery?.id, webhook.id, 1, 0, String(err));
  }
}

async function scheduleRetry(
  deliveryId: string | undefined,
  webhookId: string,
  currentAttempt: number,
  status: number,
  body: string
): Promise<void> {
  if (!deliveryId) return;

  if (currentAttempt >= MAX_ATTEMPTS) {
    await getDb()
      .from("webhook_deliveries")
      .update({
        response_status: status,
        response_body: body.slice(0, 1000),
        next_retry_at: null,
      })
      .eq("id", deliveryId);

    await getDb()
      .from("webhooks")
      .update({ failure_count: MAX_ATTEMPTS, last_delivery_status: status })
      .eq("id", webhookId);
    return;
  }

  const nextRetry = new Date(Date.now() + RETRY_BACKOFF_MS[currentAttempt - 1]).toISOString();

  await getDb()
    .from("webhook_deliveries")
    .update({
      response_status: status,
      response_body: body.slice(0, 1000),
      next_retry_at: nextRetry,
    })
    .eq("id", deliveryId);
}

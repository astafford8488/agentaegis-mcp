// Stripe top-up payment flow.
//
// Two endpoints:
//   POST /v1/customers/:id/checkout-session  → returns a Stripe Checkout URL
//   POST /webhooks/stripe                    → receives checkout.session.completed
//                                              and credits the customer's prepaid balance
//
// We don't pull in the stripe SDK — direct REST calls keep deps minimal.
// Stripe API ref: https://stripe.com/docs/api

import * as crypto from "crypto";

const STRIPE_API = "https://api.stripe.com/v1";

export interface CreateCheckoutInput {
  customer_id: string;
  customer_email: string;
  amount_usd: number;       // e.g. 50.00
  success_url: string;
  cancel_url: string;
}

export interface CheckoutSession {
  id: string;
  url: string;
  expires_at: number;
}

function authHeaders() {
  const key = process.env.STRIPE_SECRET_KEY;
  if (!key) throw new Error("STRIPE_SECRET_KEY not configured");
  return {
    Authorization: `Bearer ${key}`,
    "Content-Type": "application/x-www-form-urlencoded",
  };
}

function form(params: Record<string, string | number | undefined>): string {
  const u = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null) u.append(k, String(v));
  }
  return u.toString();
}

export async function createCheckoutSession(input: CreateCheckoutInput): Promise<CheckoutSession> {
  // Validate amount — minimum $5, maximum $5000 per top-up
  if (input.amount_usd < 5) throw new Error("Minimum top-up is $5.00");
  if (input.amount_usd > 5000) throw new Error("Maximum top-up is $5000.00 per transaction");

  const cents = Math.round(input.amount_usd * 100);

  const body = form({
    "mode": "payment",
    "success_url": input.success_url + "?session_id={CHECKOUT_SESSION_ID}",
    "cancel_url": input.cancel_url,
    "customer_email": input.customer_email,
    "line_items[0][price_data][currency]": "usd",
    "line_items[0][price_data][product_data][name]": "AgentAegis API credit",
    "line_items[0][price_data][product_data][description]": `Prepaid balance — $${input.amount_usd.toFixed(2)} for tool calls`,
    "line_items[0][price_data][unit_amount]": cents,
    "line_items[0][quantity]": 1,
    "client_reference_id": input.customer_id,
    "metadata[customer_id]": input.customer_id,
    "metadata[amount_usd]": input.amount_usd.toFixed(2),
    "payment_intent_data[metadata][customer_id]": input.customer_id,
    "payment_intent_data[metadata][amount_usd]": input.amount_usd.toFixed(2),
  });

  const r = await fetch(`${STRIPE_API}/checkout/sessions`, {
    method: "POST",
    headers: authHeaders(),
    body,
  });

  if (!r.ok) {
    const errorBody = await r.text();
    throw new Error(`Stripe checkout creation failed: ${r.status} ${errorBody.slice(0, 200)}`);
  }

  const session = await r.json();
  return {
    id: session.id,
    url: session.url,
    expires_at: session.expires_at,
  };
}

/**
 * Verify a Stripe webhook signature. Stripe signs all webhook bodies with
 * a shared secret (STRIPE_WEBHOOK_SECRET). Without verification we'd be
 * vulnerable to anyone spoofing payment-completed events to credit balances.
 *
 * Reference: https://stripe.com/docs/webhooks/signatures
 */
export function verifyWebhookSignature(payload: string, signatureHeader: string, secret: string, toleranceSeconds = 300): boolean {
  if (!signatureHeader) return false;

  // Stripe-Signature header: t=timestamp,v1=hmac,v1=hmac,v0=hmac
  const parts = Object.fromEntries(
    signatureHeader.split(",").map((p) => p.split("=") as [string, string])
  );
  const timestamp = parts["t"];
  const signatures: string[] = signatureHeader.split(",").filter((p) => p.startsWith("v1=")).map((p) => p.slice(3));

  if (!timestamp || signatures.length === 0) return false;

  // Replay protection: reject events older than tolerance
  const ts = parseInt(timestamp);
  if (Math.abs(Date.now() / 1000 - ts) > toleranceSeconds) return false;

  const signedPayload = `${timestamp}.${payload}`;
  const expected = crypto.createHmac("sha256", secret).update(signedPayload, "utf8").digest("hex");

  // Constant-time comparison
  return signatures.some((sig) => {
    if (sig.length !== expected.length) return false;
    try {
      return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
    } catch {
      return false;
    }
  });
}

export interface StripeCheckoutCompletedEvent {
  customer_id: string;
  amount_usd: number;
  payment_intent: string;
  session_id: string;
  customer_email: string;
}

export function parseCheckoutCompleted(event: any): StripeCheckoutCompletedEvent | null {
  if (event.type !== "checkout.session.completed") return null;
  const session = event.data?.object;
  if (!session) return null;
  if (session.payment_status !== "paid") return null;

  const customerId = session.client_reference_id || session.metadata?.customer_id;
  const amountUsd = session.amount_total ? session.amount_total / 100 : null;

  if (!customerId || amountUsd === null) return null;

  return {
    customer_id: customerId,
    amount_usd: amountUsd,
    payment_intent: session.payment_intent,
    session_id: session.id,
    customer_email: session.customer_email || session.customer_details?.email || "",
  };
}

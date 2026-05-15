/**
 * CDP-mode x402 facilitator integration.
 *
 * Coinbase Developer Platform (CDP) hosts the only public x402 facilitator
 * currently supporting Base mainnet. The open x402.org reference facilitator
 * dropped Base mainnet support 2026-05-13 — only testnet remains. Migrating
 * to CDP requires three things the legacy raw-fetch path didn't handle:
 *
 * 1. JWT-signed Authorization headers. The SDK's `facilitator` config
 *    (from @coinbase/x402) reads CDP_API_KEY_ID + CDP_API_KEY_SECRET env
 *    vars and produces signed Authorization + X-Correlation-Id headers
 *    automatically. We don't generate JWTs ourselves.
 *
 * 2. x402 protocol v2 wire format. The differences from v1:
 *      - network is chain-id format (e.g. "eip155:8453") not "base"
 *      - PaymentRequirements uses `amount` (not `maxAmountRequired`)
 *      - resource lives in the outer PaymentRequired envelope as a
 *        ResourceInfo object, not on each requirements entry
 *      - x402Version: 2 in the challenge
 *
 * 3. SDK call signature for verify/settle. We hand the SDK a v2 payload
 *    plus v2 requirements; it handles HTTP, auth, retries, and zod
 *    validation internally.
 *
 * This file isolates all of the above. The legacy raw-fetch path in
 * x402Auth.ts is unchanged and remains the default for any deployment that
 * doesn't have CDP credentials set (testnet, self-hosted facilitators, or
 * future facilitator providers that accept v1 + raw bearer auth).
 *
 * Mode selection: `isCdpMode()` returns true iff both CDP_API_KEY_ID AND
 * CDP_API_KEY_SECRET env vars are set. Presence of credentials IS the flag —
 * no separate X402_FACILITATOR_MODE knob to keep in sync.
 */

import { facilitator } from "@coinbase/x402";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { TOOL_PRICING } from "../types/mcp.js";

/** Map v1 short-name networks → v2 chain-id format. */
const V1_TO_V2_NETWORK: Record<string, `${string}:${string}`> = {
  base: "eip155:8453",
  "base-sepolia": "eip155:84532",
  ethereum: "eip155:1",
};

/** USDC contract addresses keyed by v2 chain-id network. */
const V2_NETWORK_TO_USDC: Record<string, string> = {
  "eip155:8453": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  "eip155:84532": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
  "eip155:1": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
};

/** USDC EIP-712 typed-data domain (same across testnet/mainnet for Circle's contract). */
const USDC_EIP712_DOMAIN = { name: "USDC", version: "2" };

let cachedClient: HTTPFacilitatorClient | null = null;

function getCdpClient(): HTTPFacilitatorClient {
  if (!cachedClient) {
    cachedClient = new HTTPFacilitatorClient(facilitator);
  }
  return cachedClient;
}

/** True iff both CDP credentials are present in the environment. */
export function isCdpMode(): boolean {
  return Boolean(process.env.CDP_API_KEY_ID && process.env.CDP_API_KEY_SECRET);
}

/**
 * Translate X402_NETWORK (which may be a v1 short name or a v2 chain-id)
 * into v2 chain-id format. Pass-through if already v2.
 */
export function toV2Network(network: string): `${string}:${string}` {
  if (network.includes(":")) return network as `${string}:${string}`;
  const v2 = V1_TO_V2_NETWORK[network];
  if (v2) return v2;
  // Fall back to a recognizable invalid value so the facilitator returns
  // a clean "unsupported network" error instead of a cryptic 400.
  return `unknown:${network}` as `${string}:${string}`;
}

/** v2 PaymentRequirements shape (matches @x402/core's PaymentRequirements type). */
export interface CdpPaymentRequirements {
  scheme: "exact";
  network: `${string}:${string}`;
  asset: string;
  amount: string;
  payTo: string;
  maxTimeoutSeconds: number;
  extra: Record<string, unknown>;
}

/** Build v2 PaymentRequirements for a tool call. Reads X402_PAYEE_ADDRESS, X402_NETWORK, X402_ASSET env vars. */
export function buildCdpPaymentRequirements(toolName: string): CdpPaymentRequirements {
  const priceUsd = TOOL_PRICING[toolName] || 0;
  const amount = String(Math.round(priceUsd * 1_000_000)); // USDC has 6 decimals

  const v1Network = process.env.X402_NETWORK || "base-sepolia";
  const network = toV2Network(v1Network);
  const asset = V2_NETWORK_TO_USDC[network] || process.env.X402_ASSET || "USDC";
  const payTo = process.env.X402_PAYEE_ADDRESS || "";

  return {
    scheme: "exact",
    network,
    asset,
    amount,
    payTo,
    maxTimeoutSeconds: 60,
    extra: USDC_EIP712_DOMAIN,
  };
}

/** v2 PaymentRequired challenge envelope for the 402 response body. */
export interface CdpChallenge {
  x402Version: 2;
  error: string;
  resource: { url: string; description?: string; mimeType?: string };
  accepts: CdpPaymentRequirements[];
}

/** Build the full 402 challenge body for a tool call. */
export function buildCdpChallenge(toolName: string, resourceUrl: string): CdpChallenge {
  return {
    x402Version: 2,
    error: "X-PAYMENT header is required",
    resource: {
      url: resourceUrl,
      description: `AgentAegis ${toolName} — single tool invocation`,
      mimeType: "application/json",
    },
    accepts: [buildCdpPaymentRequirements(toolName)],
  };
}

export interface CdpVerifyResult {
  isValid: boolean;
  payerAddress?: string;
  invalidReason?: string;
}

export interface CdpSettleResult {
  success: boolean;
  txHash?: string;
  network?: string;
  error?: string;
}

/**
 * Verify a payment via the CDP facilitator. The SDK adds JWT-signed
 * Authorization headers, calls /verify, and zod-validates the response.
 *
 * Returns the same shape as the legacy verifyX402Payment so callers don't
 * have to branch on success.
 */
export async function cdpVerify(
  paymentPayload: unknown,
  paymentRequirements: CdpPaymentRequirements,
): Promise<CdpVerifyResult> {
  try {
    // The SDK validates both inputs with zod. We cast to `never` because our
    // decoded X-PAYMENT structure originates from an untrusted agent and is
    // type-erased; the SDK does the structural checking. Same for
    // paymentRequirements — our type is structurally compatible but TS can't
    // see through the SDK's internal branded types without a hard cast.
    const raw = (await getCdpClient().verify(
      paymentPayload as never,
      paymentRequirements as never,
    )) as {
      isValid?: boolean;
      payer?: string;
      invalidReason?: string;
      invalidMessage?: string;
    };
    return {
      isValid: Boolean(raw.isValid),
      payerAddress: raw.payer,
      invalidReason: raw.invalidReason || raw.invalidMessage,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { isValid: false, invalidReason: `CDP verify exception: ${msg.slice(0, 300)}` };
  }
}

/**
 * Settle a payment via the CDP facilitator. Same auth and validation
 * mechanics as cdpVerify. Returns the transaction hash on success.
 */
export async function cdpSettle(
  paymentPayload: unknown,
  paymentRequirements: CdpPaymentRequirements,
): Promise<CdpSettleResult> {
  try {
    const raw = (await getCdpClient().settle(
      paymentPayload as never,
      paymentRequirements as never,
    )) as {
      success?: boolean;
      transaction?: string;
      network?: string;
      errorReason?: string;
      errorMessage?: string;
    };
    return {
      success: Boolean(raw.success),
      txHash: raw.transaction,
      network: raw.network,
      error: raw.errorReason || raw.errorMessage,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, error: `CDP settle exception: ${msg.slice(0, 300)}` };
  }
}

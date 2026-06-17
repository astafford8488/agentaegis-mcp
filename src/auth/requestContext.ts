// Request context — threads the authenticated API key through async calls
// so MCP tool handlers can access it without explicit parameter passing.
//
// The MCP SDK's tool handler signature doesn't include a request context,
// so we lean on Node's AsyncLocalStorage. The HTTP transport runs each
// request in a context store; tools read from it via getRequestContext().

import { AsyncLocalStorage } from "async_hooks";
import type { APIKey } from "../db/types.js";
import type { Agent } from "../db/agents.js";

export interface RequestContext {
  apiKey?: APIKey;
  authMethod?: "api_key" | "x402" | "none";
  paymentRef?: string;
  /** Set by the /mcp x402 gate when payment has been verified + settled.
   *  wrapTool sees this and skips its own payment check (call already paid for). */
  x402Settled?: boolean;
  /** x402 payer wallet (lowercased 0x…), set by the gate after settlement. The
   *  identity anchor for the x402 rail. */
  payerWallet?: string;
  /** Resolved Phase 9.0 agent identity. Lazily populated + memoized by
   *  getOrResolveAgent so a request resolves identity at most once. */
  agent?: Agent;
  ip?: string;
  userAgent?: string;
}

const storage = new AsyncLocalStorage<RequestContext>();

export function runWithContext<T>(ctx: RequestContext, fn: () => T): T {
  return storage.run(ctx, fn);
}

export function getRequestContext(): RequestContext | undefined {
  return storage.getStore();
}

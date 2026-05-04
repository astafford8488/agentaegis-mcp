// Request context — threads the authenticated API key through async calls
// so MCP tool handlers can access it without explicit parameter passing.
//
// The MCP SDK's tool handler signature doesn't include a request context,
// so we lean on Node's AsyncLocalStorage. The HTTP transport runs each
// request in a context store; tools read from it via getRequestContext().

import { AsyncLocalStorage } from "async_hooks";
import type { APIKey } from "../db/types.js";

export interface RequestContext {
  apiKey?: APIKey;
  authMethod?: "api_key" | "x402" | "none";
  paymentRef?: string;
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

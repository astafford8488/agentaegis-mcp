/**
 * x402 Bazaar discovery catalog.
 *
 * The Coinbase Bazaar is the discovery layer for agentic commerce — a searchable
 * index where AI agents find x402-payable services. Listing is automatic: the CDP
 * facilitator catalogs a resource the first time it SETTLES a payment whose
 * `paymentPayload.extensions.bazaar` carries a valid discovery declaration.
 *
 * We don't use the SDK's resource-server middleware (we have a custom CDP gate),
 * so we wire discovery ourselves: the declaration is BOTH attached to the 402
 * challenge's `extensions` (for any client that echoes it) AND injected
 * server-side into `paymentPayload.extensions` just before settle (cdpSettle) —
 * because most clients, including @x402/fetch, do NOT echo challenge extensions
 * back into the signed payment. The facilitator runs extractDiscoveryInfo over
 * `paymentPayload.extensions` on settle to index the resource. Net effect: each
 * tool is indexed in the Bazaar the first time an agent pays for it, regardless
 * of client behavior.
 *
 * This is purely additive metadata — `buildBazaarExtension` is best-effort and
 * never throws, so a bad declaration can never break a payment challenge.
 */

import { declareDiscoveryExtension } from "@x402/extensions/bazaar";
import { toolMeta } from "../toolCatalog.js";

// Discovery metadata now comes from TOOL_CATALOG (src/toolCatalog.ts). This map
// used to be maintained by hand and had silently fallen behind: it was missing
// vet_endpoint, scan_mcp_plugin and scan_skill entirely, so a 402 challenge for
// the flagship trust tools advertised "single tool invocation" and carried no
// Bazaar declaration at all.

/**
 * Build the `{ bazaar: <discovery extension> }` object for a tool, suitable for
 * the 402 challenge's `extensions` field. Best-effort: returns undefined (never
 * throws) so discovery can never break a payment challenge.
 */
export function buildBazaarExtension(toolName: string): Record<string, unknown> | undefined {
  const meta = toolMeta(toolName);
  if (!meta?.discovery || !meta.inputSchema) return undefined;
  try {
    return declareDiscoveryExtension({
      toolName,
      description: meta.discovery,
      inputSchema: meta.inputSchema,
    });
  } catch {
    return undefined;
  }
}

/** Agent-facing one-line description for a tool, used as the resource description. */
export function toolDiscoveryDescription(toolName: string): string | undefined {
  return toolMeta(toolName)?.discovery;
}

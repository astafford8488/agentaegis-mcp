import { describe, it, expect } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { buildMcpServer } from "../src/server.js";
import { TOOL_CATALOG, toolMeta } from "../src/toolCatalog.js";
import { TOOL_PRICING } from "../src/types/mcp.js";
import { buildBazaarExtension, toolDiscoveryDescription } from "../src/auth/bazaarCatalog.js";

// TOOL_CATALOG is the single source of tool copy. Before it existed the same
// text lived in four places and drifted: the Bazaar map was missing the entire
// trust layer, so a 402 for vet_endpoint advertised "single tool invocation".
// These tests exist so that specific failure cannot recur silently.

async function connect() {
  const server = buildMcpServer({ skipPayment: true });
  const client = new Client({ name: "test", version: "0.0.0" });
  const [c, s] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(s), client.connect(c)]);
  return client;
}

const paidTools = Object.entries(TOOL_PRICING)
  .filter(([, price]) => price > 0)
  .map(([name]) => name);

describe("catalog coverage", () => {
  it("has an entry for every priced tool", () => {
    for (const name of paidTools) {
      expect(toolMeta(name), `${name} is priced but missing from TOOL_CATALOG`).toBeTruthy();
    }
  });

  it("prices every catalog entry", () => {
    for (const name of Object.keys(TOOL_CATALOG)) {
      expect(TOOL_PRICING[name], `${name} is in TOOL_CATALOG but missing from TOOL_PRICING`).toBeDefined();
    }
  });

  it("gives every paid tool Bazaar discovery metadata", () => {
    // The original bug: vet_endpoint, scan_mcp_plugin and scan_skill had none,
    // so they were unlistable and their 402 challenge had placeholder copy.
    for (const name of paidTools) {
      const meta = toolMeta(name)!;
      expect(meta.discovery, `${name} has no discovery description`).toBeTruthy();
      expect(meta.inputSchema, `${name} has no discovery inputSchema`).toBeTruthy();
    }
  });

  it("builds a Bazaar extension for the trust-layer flagship", () => {
    for (const name of ["vet_endpoint", "scan_mcp_plugin", "scan_skill"]) {
      expect(toolDiscoveryDescription(name), `${name} discovery description`).toBeTruthy();
      expect(buildBazaarExtension(name), `${name} bazaar extension`).toBeTruthy();
    }
  });

  it("keeps descriptions free of hardcoded prices", () => {
    // Price is appended centrally from TOOL_PRICING; a dollar figure written
    // into the copy would be a second source of truth that silently goes stale.
    for (const [name, meta] of Object.entries(TOOL_CATALOG)) {
      expect(meta.description, `${name} hardcodes a price`).not.toMatch(/\$\d/);
    }
  });
});

describe("annotations", () => {
  it("annotates every registered tool", async () => {
    const client = await connect();
    const { tools } = await client.listTools();
    for (const t of tools) {
      expect(t.annotations, `${t.name} has no annotations`).toBeTruthy();
      expect(t.annotations!.readOnlyHint, `${t.name} readOnlyHint`).toBeTypeOf("boolean");
      expect(t.annotations!.openWorldHint, `${t.name} openWorldHint`).toBeTypeOf("boolean");
    }
  });

  it("marks the traffic-sending scanners as NOT read-only", async () => {
    const client = await connect();
    const { tools } = await client.listTools();

    // These send probe traffic that can trip IDS or destabilise a service.
    // Marking them read-only would invite clients to auto-approve them.
    for (const name of ["vuln_scan_network", "vuln_scan_web_app"]) {
      const t = tools.find((x) => x.name === name)!;
      expect(t.annotations!.readOnlyHint, `${name} must not be read-only`).toBe(false);
      expect(t.annotations!.openWorldHint).toBe(true);
    }

    // Everything else must be read-only: nothing else changes a target's state.
    for (const t of tools) {
      if (t.name.startsWith("vuln_scan_")) continue;
      expect(t.annotations!.readOnlyHint, `${t.name} should be read-only`).toBe(true);
    }
  });

  it("marks free account tools as closed-world", async () => {
    const client = await connect();
    const { tools } = await client.listTools();
    for (const name of ["help", "account_balance", "agent_whoami"]) {
      const t = tools.find((x) => x.name === name)!;
      expect(t.annotations!.openWorldHint, `${name} only reads our own data`).toBe(false);
    }
  });

  it("marks tools that call third parties as open-world", async () => {
    const client = await connect();
    const { tools } = await client.listTools();
    for (const name of ["cve_lookup", "threat_intel_lookup", "vet_endpoint", "dependency_audit"]) {
      const t = tools.find((x) => x.name === name)!;
      expect(t.annotations!.openWorldHint, `${name} reaches external services`).toBe(true);
    }
  });
});

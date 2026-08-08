import { describe, it, expect } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { buildMcpServer } from "../src/server.js";
import { buildServerInstructions } from "../src/instructions.js";
import { TOOL_PRICING, formatUsd } from "../src/types/mcp.js";

// The server `instructions` string and the prompt catalog are the guidance that
// reaches an agent with nothing installed on the caller's side. Both are easy to
// break silently — a renamed tool or a repriced call leaves stale text that
// misroutes every connecting agent — so these tests assert against TOOL_PRICING
// and a live MCP handshake rather than against copy.

async function connect() {
  const server = buildMcpServer({ skipPayment: true });
  const client = new Client({ name: "test", version: "0.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return { client, server };
}

describe("server instructions", () => {
  it("is advertised to clients on initialize", async () => {
    const { client } = await connect();
    const instructions = client.getInstructions();
    expect(instructions).toBeTruthy();
    expect(instructions!.length).toBeGreaterThan(500);
  });

  it("names every registered tool at its real price", () => {
    const text = buildServerInstructions({ includeCredentialCheck: true });

    for (const [tool, price] of Object.entries(TOOL_PRICING)) {
      expect(text, `${tool} missing from instructions`).toContain(tool);
      if (price > 0) {
        // The tool must appear in its own price tier, not merely somewhere.
        const tier = text
          .split("\n")
          .find((l) => l.startsWith(`- $${String(price).replace(/\.00$/, "").replace(/^(\d+)$/, "$1")}`) && l.includes(tool));
        expect(tier, `${tool} not listed under $${price}`).toBeTruthy();
      }
    }
  });

  it("lists the free tools as free", () => {
    const text = buildServerInstructions();
    const freeLine = text.split("\n").find((l) => l.startsWith("- Free:"));
    expect(freeLine).toBeTruthy();
    for (const [tool, price] of Object.entries(TOOL_PRICING)) {
      if (price === 0) expect(freeLine).toContain(tool);
    }
  });

  it("omits credential_check unless HIBP is configured", () => {
    // credential_check is only registered when HIBP_API_KEY is set; advertising
    // it otherwise points agents at a tool that does not exist.
    expect(buildServerInstructions({ includeCredentialCheck: false })).not.toContain("credential_check");
    expect(buildServerInstructions({ includeCredentialCheck: true })).toContain("credential_check");
  });

  it("tells agents to reuse prior scans and confirm spend before paying", () => {
    const text = buildServerInstructions();
    expect(text).toContain("agent_history");
    expect(text).toContain("agent_scan_get");
    expect(text).toMatch(/before the first paid call/i);
  });

  it("flags the active scanners as needing authorization", () => {
    const text = buildServerInstructions();
    expect(text).toMatch(/vuln_scan_network and vuln_scan_web_app send real traffic/i);
  });
});

describe("tool descriptions", () => {
  it("advertises each paid tool's real price", async () => {
    const { client } = await connect();
    const { tools } = await client.listTools();

    for (const tool of tools) {
      const price = TOOL_PRICING[tool.name] ?? 0;
      if (price === 0) continue;
      expect(tool.description, `${tool.name} has no description`).toBeTruthy();
      expect(tool.description, `${tool.name} must advertise ${formatUsd(price)}`).toContain(
        `Costs ${formatUsd(price)} per call.`
      );
    }
  });

  it("gives every tool enough description to route on", async () => {
    const { client } = await connect();
    const { tools } = await client.listTools();

    expect(tools.length).toBeGreaterThan(20);
    for (const tool of tools) {
      // The old one-liners ("Look up CVE details, CVSS scores, and patches.")
      // gave an agent nothing to choose between 28 tools on.
      expect(tool.description!.length, `${tool.name} description is too thin`).toBeGreaterThan(80);
    }
  });

  it("warns that the active scanners send real traffic", async () => {
    const { client } = await connect();
    const { tools } = await client.listTools();

    for (const name of ["vuln_scan_network", "vuln_scan_web_app"]) {
      const tool = tools.find((t) => t.name === name);
      expect(tool, `${name} not registered`).toBeTruthy();
      expect(tool!.description).toMatch(/SENDS REAL TRAFFIC/);
      expect(tool!.description).toMatch(/authoriz/i);
    }
  });
});

describe("prompts", () => {
  it("advertises the guided workflows", async () => {
    const { client } = await connect();
    const { prompts } = await client.listPrompts();
    const names = prompts.map((p) => p.name).sort();
    expect(names).toEqual([
      "compliance_readiness",
      "incident_response",
      "pre_install_trust_check",
      "security_audit",
    ]);
    for (const p of prompts) expect(p.description, `${p.name} needs a description`).toBeTruthy();
  });

  it("renders a workflow without executing any tool", async () => {
    const { client } = await connect();
    const res = await client.getPrompt({ name: "security_audit", arguments: { target: "example.com" } });
    const text = res.messages.map((m) => (m.content as { text: string }).text).join("\n");

    expect(text).toContain("example.com");
    expect(text).toContain("dns_security_check");
    // Passive by default: the traffic-sending scan must not be in the plan.
    expect(text).not.toContain("vuln_scan_network");
  });

  it("gates the active scan behind depth=full and an authorization check", async () => {
    const { client } = await connect();
    const res = await client.getPrompt({
      name: "security_audit",
      arguments: { target: "example.com", depth: "full" },
    });
    const text = res.messages.map((m) => (m.content as { text: string }).text).join("\n");

    expect(text).toContain("vuln_scan_network");
    expect(text).toMatch(/authorized to test/i);
  });

  it("routes trust checks to the right scanner per source kind", async () => {
    const { client } = await connect();

    const mcp = await client.getPrompt({
      name: "pre_install_trust_check",
      arguments: { source: "https://github.com/example/some-mcp", kind: "mcp_server" },
    });
    expect((mcp.messages[0].content as { text: string }).text).toContain("scan_mcp_plugin");

    const skill = await client.getPrompt({
      name: "pre_install_trust_check",
      arguments: { source: "https://github.com/example/some-skill", kind: "skill" },
    });
    expect((skill.messages[0].content as { text: string }).text).toContain("scan_skill");

    // With no kind, the agent gets the routing rules for all three.
    const inferred = await client.getPrompt({
      name: "pre_install_trust_check",
      arguments: { source: "https://example.com/mystery" },
    });
    const text = (inferred.messages[0].content as { text: string }).text;
    expect(text).toContain("scan_mcp_plugin");
    expect(text).toContain("scan_skill");
    expect(text).toContain("vet_endpoint");
  });

  it("quotes costs that match TOOL_PRICING", async () => {
    const { client } = await connect();
    const res = await client.getPrompt({
      name: "compliance_readiness",
      arguments: { framework: "SOC 2" },
    });
    const text = (res.messages[0].content as { text: string }).text;

    // control_gap_analysis is $2; a drift in pricing must fail here, not ship.
    expect(text).toContain(`control_gap_analysis ($${TOOL_PRICING.control_gap_analysis})`);
    expect(text).toContain("SOC 2");
  });
});

# MCP registry submission package

The MCP ecosystem has multiple directories. They have different policies — some accept hosted/paid services, some require open-source self-hostable servers. AgentAegis is a hosted, paid service, so the submission strategy varies per directory.

This document is the **canonical submission text and metadata** that we submit verbatim. The PitchIQ mirror under Launch is the review surface — edit here (repo is canonical), then sync changes to PitchIQ before submitting.

## Status (2026-06-16)

✅ **Official MCP Registry — PUBLISHED.** AgentAegis is live in the canonical, API-backed registry at `registry.modelcontextprotocol.io` as `io.github.astafford8488/agentaegis` v0.3.0 (published via `mcp-publisher` + the repo's `server.json`). This is the registry MCP clients query — **distinct from** the `modelcontextprotocol/servers` GitHub awesome-list below, which is still a separate PR.

**Remaining directory submissions:** smithery.ai, mcp.so, glama.ai (copy below). Lead each with "already listed in the official MCP registry" as social proof. The `modelcontextprotocol/servers` GitHub PR is optional and lowest-priority now that the API registry carries us.

## Reality check — is AgentAegis directory-eligible?

| Directory | Accepts hosted/paid? | Requires open source? | Verdict |
|---|---|---|---|
| **modelcontextprotocol/servers** (official) | Yes (separate "Hosted" section) | No | ✅ Submit |
| **smithery.ai** | Yes (designed for hosted) | No | ✅ Submit |
| **mcp.so** | Yes | No | ✅ Submit |
| **glama.ai/mcp** | Yes | No | ✅ Submit |
| **mcp-get** (CLI installer) | No | Yes — must clone-and-run | ❌ Skip (until we have an open-source companion package) |

**Recommendation:** Submit to the four ✅ directories. For the OSS-only directories, plan a separate open-source companion package (`@agentaegis/mcp-client` or similar — a thin TypeScript SDK that wraps the hosted endpoint with type-safe helpers). That gets you in those directories AND drives lower-friction integration.

## Submission 1 — modelcontextprotocol/servers

**Where:** GitHub PR to `https://github.com/modelcontextprotocol/servers`
**Section:** README.md → "🌎 Third-Party Servers" → likely under "🛠️ Official Integrations" or a new "💼 Commercial / Hosted" section depending on current README structure
**Format:** A bullet under the appropriate section

### PR body (copy/paste into PR description)

```
This PR adds AgentAegis to the third-party servers list under [section].

AgentAegis is a hosted MCP server that acts as a security & trust layer
for AI agents. Its flagship tools target the agent ecosystem's own
supply-chain risk:
  - scan_mcp_plugin — scan an MCP server (git repo or code) for
    exfiltration, prompt-injection sinks, dangerous capabilities, install
    hooks and obfuscation BEFORE an agent installs/trusts it
  - scan_skill — the same trust scan for an agent skill (SKILL.md + scripts)
  - vet_endpoint — a PROCEED/CAUTION/BLOCK safety verdict for an endpoint
    an agent is about to call or pay (TLS, DNS, threat-intel, domain age)

Plus 25 more cybersecurity tools: vulnerability scans, threat intel
(NVD/AbuseIPDB/OTX/abuse.ch), compliance (SOC 2, ISO 27001, HIPAA, PCI DSS),
code security (SAST, secret scanning, dependency audit), and identity
(access review, MFA audit) — 28 tools total.

Billing is per-call on two rails: pre-funded API keys (Stripe-backed) or
per-call USDC micropayments via the x402 protocol on Base mainnet. A free
tier covers tools/list, help, and account_balance, so agents can discover
capabilities without payment. Paid tools are $1–$5/call.

The server is publicly reachable at:
  https://agentaegis-mcp-production.up.railway.app/mcp

Production status:
- Live on Base mainnet with real x402 settlements (verifiable on-chain)
- Already listed in the official MCP registry (io.github.astafford8488/agentaegis)
- 6 tools also listed in the Coinbase x402 Bazaar
- Status page: https://status.agentaegis.org
- Public FAQ: https://agentaegis-mcp-production.up.railway.app/faq

Per the README's contribution guidelines, this is added under [hosted/
third-party] because the server is not self-hostable open source — the
billing engine is proprietary while the marketing site, FAQ, and
specification are public.

Happy to adjust the description, section, or formatting per maintainer
guidance.
```

### README entry (copy/paste into README.md)

```markdown
- **[AgentAegis](https://www.agentaegis.org)** — security & trust layer for AI agents: scan an MCP server or skill *before* you install it (`scan_mcp_plugin`, `scan_skill`) and vet an endpoint before you pay it (`vet_endpoint`), plus 25 more cybersecurity tools (vuln scans, threat intel, compliance, code security, identity). Per-call billing via API key or x402 USDC; free discovery tier. Hosted.
```

### Pre-submission checklist

- [ ] Read the current `CONTRIBUTING.md` of `modelcontextprotocol/servers` for any updated rules
- [ ] Verify there's a section appropriate to a hosted, paid service
- [ ] If no such section exists, propose one in the PR body (don't unilaterally create)
- [ ] Confirm the entry stays alphabetized within its section
- [ ] Sign your commits if the repo requires it (`git commit -S`)

---

## Submission 2 — smithery.ai

**Where:** https://smithery.ai/new (web form)
**Format:** Form fill with a `smithery.json` configuration file

### `smithery.json` (place at repo root if Smithery requires)

```json
{
  "name": "agentaegis",
  "displayName": "AgentAegis",
  "description": "20 cybersecurity tools for AI agents — vuln scans, compliance checks, threat intel, code security, identity audits. Per-call billing via API key or x402 USDC.",
  "icon": "https://www.agentaegis.org/icon.png",
  "homepage": "https://www.agentaegis.org",
  "repository": "https://github.com/astafford8488/agentaegis-mcp",
  "license": "Proprietary (hosted SaaS)",
  "categories": ["security", "operations", "compliance"],
  "transport": "streamable-http",
  "url": "https://agentaegis-mcp-production.up.railway.app/mcp",
  "auth": {
    "type": "bearer",
    "header": "Authorization",
    "format": "Bearer {api_key}",
    "obtain": "https://www.agentaegis.org/pay",
    "alternative": {
      "type": "x402",
      "description": "Per-call HTTP 402 + ERC-3009 USDC settlement on Base mainnet (no signup required)"
    }
  },
  "configSchema": {
    "type": "object",
    "properties": {
      "apiKey": {
        "type": "string",
        "description": "AgentAegis API key (starts with aegis_). Get one at agentaegis.org/pay or use x402 for per-call payments without an API key.",
        "required": false
      }
    }
  }
}
```

### Form fields

| Field | Value |
|---|---|
| Name | AgentAegis |
| Description | 20 cybersecurity tools for AI agents — pay per call via API key or USDC. Free discovery tier. |
| Category | Security · Operations · Compliance (multi-select) |
| Author | Andrew Stafford |
| Author URL | https://www.agentaegis.org |
| Homepage | https://www.agentaegis.org |
| GitHub | https://github.com/astafford8488/agentaegis-mcp |
| MCP endpoint | https://agentaegis-mcp-production.up.railway.app/mcp |
| Tags | cybersecurity, vulnerability-scanning, compliance, x402, payments, threat-intel |

### Pre-submission checklist

- [ ] Verify Smithery's current submission flow (it changes — check smithery.ai/docs)
- [ ] Confirm whether they want the `smithery.json` committed to the repo or pasted in the form
- [ ] If they fetch the icon from a URL, confirm `https://www.agentaegis.org/icon.png` is set up (currently a TODO — update marketing site to expose a square icon at that path)

---

## Submission 3 — mcp.so

**Where:** https://mcp.so/submit (form-based)

### Form fields

| Field | Value |
|---|---|
| Name | AgentAegis |
| Description | A hosted MCP server with 20 cybersecurity tools. Pay per call via Stripe API key or per-call USDC (x402). Free tier for tool discovery. Patent pending. |
| Category | Security |
| Author / Maintainer | Andrew Stafford |
| Repository URL | https://github.com/astafford8488/agentaegis-mcp |
| Homepage | https://www.agentaegis.org |
| MCP endpoint | https://agentaegis-mcp-production.up.railway.app/mcp |
| License | Proprietary / SaaS |
| Tags | security, vulnerability-management, compliance, threat-intel, x402, payments, autonomous-agents |

### Description (longer, if mcp.so allows ~500 chars)

```
AgentAegis exposes 20 cybersecurity tools to AI agents through a single MCP endpoint with per-call billing on two rails: pre-funded API keys (Stripe-backed) or per-call USDC micropayments via the x402 protocol on Base mainnet. Free discovery tier (tools/list, help, account_balance) means agents can explore capabilities without payment. Paid tools include vuln scans, compliance checks (SOC 2, ISO 27001, HIPAA, PCI DSS), threat intelligence (NVD, AbuseIPDB, OTX, abuse.ch), code security (SAST, secret scanning, dependency audit), and identity tooling (access review, MFA audit). Patent pending on the dual-rail architecture.
```

---

## Submission 4 — glama.ai/mcp

**Where:** https://glama.ai/mcp/submit
**Format:** Form-based, accepts hosted servers

### Form fields

Mostly the same as mcp.so above. Glama-specific fields:

| Field | Value |
|---|---|
| Pricing model | Pay-per-call ($1–$5 per tool, varies by compute/data cost) |
| Free tier | Yes (discovery tools — tools/list, help, account_balance) |
| Authentication | Bearer token (API key) OR x402 (per-call USDC, no signup) |
| Self-hostable | No (hosted SaaS) |

---

## Pre-submission across all directories

- [ ] **Public icon at `agentaegis.org/icon.png`** — needed by Smithery and Glama. 256×256 or 512×512 PNG. Currently no such asset; see `agentaegis-site/public/` to add.
- [ ] **`/.well-known/mcp.json`** — some directories scrape this file from the MCP endpoint. Worth adding to the MCP server (returns the same metadata as `tools/list` plus pricing). Not required, but improves discovery.
- [ ] **CONTRIBUTING.md visible in agentaegis-mcp** — even though the repo is private, having a public CONTRIBUTING.md with "this server is closed-source; here's how to integrate" reduces friction for directory maintainers reviewing the entry.
- [ ] **Status badge** — embed `https://status.agentaegis.org` badge in submission descriptions where allowed. Signals operator seriousness.
- [ ] **Demo video** — Phase 8 Day 1 deliverable. Once recorded, include link in all directory submissions.

## Submission order (recommended)

1. **mcp.so first** — lowest bar, fastest review, gives you a "we're in directory X" social proof for higher-bar submissions
2. **glama.ai second** — similar bar, similar audience, doubles your directory presence
3. **smithery.ai third** — they have moderation; submit when the icon + well-known endpoint exist
4. **modelcontextprotocol/servers last** — official directory, highest scrutiny. You want to walk in with 3 other directory listings, the Show HN post, and the demo video as social proof.

## After-submission tracking

Track in the Notion outreach database (Launch → Cold Outreach) with category=`directory` and a status field for each submission's review state:
- `submitted`
- `under_review`
- `accepted`
- `rejected_with_reason`
- `accepted_with_changes_requested`

---

## Open-source companion package (deferred)

To unlock OSS-only directories, ship a separate small package:

**Name:** `@agentaegis/mcp-client` (npm) or `agentaegis-cli` (Python via PyPI)
**Repo:** New public repo, MIT or Apache-2.0 licensed
**What it does:**
- Thin client wrapper around the hosted endpoint
- Type-safe TypeScript helpers per tool
- Helper for x402 payment flow (uses x402-fetch under the hood)
- Helper for API key auth
- Example agent integrations (Claude Desktop config snippet, LangChain wrapper, AutoGen wrapper)

This separate package addresses:
- mcp-get directory listing
- "I want to see the source" objections from would-be users
- Discoverability via npm/PyPI search
- Demonstrates we know the MCP client side well, not just the server

**Effort:** ~1 week. Not part of Phase 8; queue for Phase 9 unless launch traction demands it sooner.

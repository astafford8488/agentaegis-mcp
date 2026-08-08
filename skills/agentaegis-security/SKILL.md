---
name: agentaegis-security
description: Run real security scans through the AgentAegis MCP server — vet an endpoint or third-party agent code before trusting it, look up CVEs and IP/domain reputation, scan a repo for vulnerabilities, secrets and vulnerable dependencies, audit DNS/TLS/email posture, or assess compliance readiness. Use when the user asks whether something is safe to install, call, pay or trust, or asks for a security, vulnerability or compliance assessment. Tools are billed per call, so this skill also covers confirming cost before spending.
license: MIT
allowed-tools: vet_endpoint, scan_mcp_plugin, scan_skill, cve_lookup, threat_intel_lookup, dns_security_check, email_security_audit, ssl_tls_audit, sast_scan, secret_scan, dependency_audit, vuln_scan_network, vuln_scan_web_app, incident_triage, vuln_prioritize, compliance_framework_check, control_gap_analysis, evidence_collect, policy_generate, audit_report_generate, access_review, mfa_audit, help, account_balance, agent_whoami, agent_history, agent_scan_get
---

# AgentAegis security scans

AgentAegis is a hosted MCP server that runs real security scanners (nmap, Nuclei, sslyze, Semgrep, trufflehog, trivy) and queries real threat-intel feeds (NVD, AbuseIPDB, AlienVault OTX, abuse.ch, HIBP). Findings describe real infrastructure.

## Setup

Add the server to your MCP client:

```json
{
  "mcpServers": {
    "agentaegis": {
      "url": "https://agentaegis-mcp-production.up.railway.app/mcp",
      "headers": { "Authorization": "Bearer aegis_YOUR_API_KEY_HERE" }
    }
  }
}
```

Get a key at https://agentaegis.org/pay. Alternatively, omit the header and pay per call in USDC on Base via x402 — no signup, the server answers with an HTTP 402 challenge your x402-capable client settles automatically.

If the tools are not available, the server is not connected. Say so rather than guessing at answers this skill is meant to measure.

## Cost — this skill spends real money

Tools cost **$1 to $5 per call**, charged when the call is made. A scan that returns nothing useful still costs.

- Before the **first paid call in a conversation**, tell the user which tool you plan to call and what it costs, and wait for their agreement.
- Never run a scan the user did not ask for. Never call paid tools to explore the catalog.
- Never retry a paid tool in a loop. On error, report it and stop.

**Free, always:** `help`, `account_balance`, `agent_whoami`, `agent_history`, `agent_scan_get`.

Call `help` for exact current pricing rather than quoting numbers from memory.

## Always check for a prior result first

Every paid scan is stored. `agent_history` lists your prior scans and `agent_scan_get` returns any one of them in full, both **free**. When the user asks about a target you have looked at before, retrieve it instead of re-paying. Only re-scan when they want fresh data or the earlier scan is stale.

## Choosing a tool

| The user is asking | Use |
|---|---|
| Is this endpoint/domain safe to call, trust or pay? | `vet_endpoint` |
| Should I install this MCP server or plugin? | `scan_mcp_plugin` |
| Should I trust this agent skill? | `scan_skill` |
| What is CVE-YYYY-NNNNN? | `cve_lookup` |
| Is this IP or domain malicious? | `threat_intel_lookup` |
| Can our email be spoofed? | `email_security_audit`, or `dns_security_check` for records only |
| Is our TLS configured correctly? | `ssl_tls_audit` |
| Are there vulnerabilities in this code? | `sast_scan` |
| Are there hardcoded secrets? | `secret_scan` |
| Are our dependencies vulnerable? | `dependency_audit` |
| What ports are exposed? | `vuln_scan_network` |
| Is this web app vulnerable? | `vuln_scan_web_app` |
| Are we SOC 2 / ISO 27001 / HIPAA / PCI-DSS / NIST CSF ready? | `compliance_framework_check` |
| We have an incident | `incident_triage` |

**Prefer `vet_endpoint` over assembling your own verdict.** It combines TLS health, DNS hygiene, threat-intel reputation and domain age into a single PROCEED / CAUTION / BLOCK decision, and costs less than running those checks separately.

## Workflows

Chain steps so each result decides whether the next is worth paying for. Pass `previous_scan_id` (the prior step's `scan_id`) on each call to keep the chain retrievable.

**Before trusting third-party agent code** — `scan_mcp_plugin` or `scan_skill`, then `vet_endpoint` on any endpoint that code calls out to. Run this *before* installation, not after.

**Assessing a repo** — `dependency_audit` → `secret_scan` → `sast_scan`. Cheapest and highest-signal first; a critical finding may end the assessment early.

**Assessing a domain** — `dns_security_check` → `email_security_audit` → `ssl_tls_audit`. Add `vuln_scan_network` only with authorization (below).

**Compliance** — `compliance_framework_check` → `control_gap_analysis`. Stop there and ask; `evidence_collect` and `audit_report_generate` are audit-preparation work that costs more than the first two combined and is wasted before the gaps are closed.

## Authorization

`vuln_scan_network` and `vuln_scan_web_app` send real traffic to the target and can trip intrusion detection. Run them **only** against hosts the user owns or is explicitly authorized to test, and confirm that before calling. If the user cannot confirm authorization, decline and offer the passive checks instead.

Everything else here is passive — public DNS, certificates, threat-intel feeds, and code the user supplied — and is safe against any target. Private, reserved and loopback addresses are rejected by design, and repository scans accept https URLs only.

## Reading results honestly

- **Verdicts are advisory.** PROCEED is not a guarantee of safety, and BLOCK is not proof of malice.
- **Reputation feeds false-positive on large infrastructure.** Cloudflare, Coinbase, Stripe and GitHub all return reputation hits. Only a curated active-malware hit is strong evidence alone. Name the feed that drove a call and how much weight it deserves.
- **A CAUTION is not a pass.** List what the user would be accepting.
- **Both active scanners can run asynchronously.** With `async: true` you get a `job_id` rather than findings; poll `GET /v1/jobs/{job_id}` with your API key. Do not call the tool again — that charges a second time.
- Lead with the most serious finding, what it means in plain language, and the concrete fix. Say what you skipped and why.

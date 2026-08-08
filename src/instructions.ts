// Server-level instructions, surfaced to every MCP client on `initialize`.
//
// Most hosts inject this string into the model's system prompt, so it is the
// only guidance that reaches an agent WITHOUT anyone installing anything. That
// makes it the highest-leverage routing surface we have: a skill has to be
// found and installed, this does not.
//
// Two consequences for anything written here:
//   1. It is charged to every conversation's context budget. Keep it dense.
//   2. It must stay true. A stale claim here misroutes every connecting agent,
//      so the price catalog is GENERATED from TOOL_PRICING rather than retyped.

import { TOOL_PRICING, formatUsd } from "./types/mcp.js";

/** Group registered tools by price tier so the catalog can never drift from billing. */
function priceCatalog(includeCredentialCheck: boolean): string {
  const byPrice = new Map<number, string[]>();

  for (const [tool, price] of Object.entries(TOOL_PRICING)) {
    // credential_check is only registered when HIBP_API_KEY is set (it has no
    // fallback source, and x402 settles before the handler runs). Listing it
    // when it isn't registered would advertise a tool that returns "unknown tool".
    if (tool === "credential_check" && !includeCredentialCheck) continue;
    const bucket = byPrice.get(price);
    if (bucket) bucket.push(tool);
    else byPrice.set(price, [tool]);
  }

  const tiers = [...byPrice.entries()].sort((a, b) => a[0] - b[0]);
  return tiers
    .map(([price, tools]) => {
      const label = price === 0 ? "Free" : formatUsd(price);
      return `- ${label}: ${tools.sort().join(", ")}`;
    })
    .join("\n");
}

export function buildServerInstructions(
  opts: { includeCredentialCheck?: boolean } = {},
): string {
  const catalog = priceCatalog(!!opts.includeCredentialCheck);

  return `AgentAegis runs real security scanners (nmap, Nuclei, sslyze, Semgrep, trufflehog, trivy) and queries real threat-intel feeds (NVD, AbuseIPDB, AlienVault OTX, abuse.ch, HIBP) on behalf of AI agents. Results are real findings about real infrastructure, not simulations.

# Paid tools spend the user's money

Every tool except the free ones below charges USD per call, billed against a prepaid API-key balance or settled per call in USDC on Base (x402). Payment is taken when the call is made, so a failed or unhelpful scan still costs money.

Because of that:
- Before the FIRST paid call in a conversation, tell the user which tool you intend to call and what it costs, and get their agreement. Named prices are below.
- Do not run scans the user did not ask for, and do not "explore" the catalog with paid calls.
- Do not retry a paid tool in a loop. If a call fails, report the error and stop.
- Prefer one composite tool over several narrow ones (see Tool selection).

Free, always, no balance required: help, account_balance, agent_whoami, agent_history, agent_scan_get. Listing tools and prompts is also free.

# Price catalog

${catalog}

# Do this before paying

- **You may have already run this scan.** Call agent_history, and if the target appears, agent_scan_get returns the full stored output. Both are free. Never re-pay for a result you already own.
- **Check funding.** account_balance reports the prepaid balance and how many of each tool remain affordable. A paid call against an empty balance fails and wastes a turn.
- **Read the FAQ instead of guessing.** help covers authentication, billing, error codes, async jobs, x402 and rate limits.

# Tool selection

Route by the question the user is actually asking.

- *"Is this endpoint / URL / domain safe to call, trust, or pay?"* → **vet_endpoint**. Returns one PROCEED / CAUTION / BLOCK verdict from TLS health, DNS hygiene, threat-intel reputation and domain age. Prefer it over calling ssl_tls_audit + dns_security_check + threat_intel_lookup separately: it costs less than the sum and returns a decision instead of three reports to reconcile.
- *"Should I install this MCP server or plugin?"* → **scan_mcp_plugin**, before installing, not after.
- *"Should I trust this agent skill / SKILL.md?"* → **scan_skill**, before loading it.
- *"What is CVE-2021-44228?"* → **cve_lookup**.
- *"Is this IP or domain malicious?"* → **threat_intel_lookup**.
- *"Is our email spoofable?"* → **email_security_audit** (full DMARC/SPF/DKIM posture) or **dns_security_check** (DNS records only, cheaper).
- *"Are there vulnerabilities in this code?"* → **sast_scan**. Hardcoded secrets → **secret_scan**. Vulnerable packages → **dependency_audit**.
- *"What ports and services are exposed?"* → **vuln_scan_network**. Web app against OWASP Top 10 → **vuln_scan_web_app**.
- *"Are we SOC 2 / ISO 27001 / HIPAA / PCI-DSS / NIST CSF ready?"* → **compliance_framework_check** first; then **control_gap_analysis** for a remediation roadmap, **evidence_collect** for audit evidence plans, **policy_generate** for policy documents, **audit_report_generate** for the final report.
- *"We have an incident."* → **incident_triage**.

# Multi-tool workflows

Chain these rather than dumping every tool at a target. Each step's output should decide whether the next one is worth its price.

1. **Vet before paying an unknown service:** vet_endpoint → if BLOCK, stop and tell the user; if CAUTION, ssl_tls_audit or threat_intel_lookup to explain why.
2. **Assess a domain:** dns_security_check → email_security_audit → vuln_scan_network (only with authorization, see below).
3. **Assess a repo:** dependency_audit → secret_scan → sast_scan, cheapest and highest-signal first.
4. **Compliance push:** compliance_framework_check → control_gap_analysis → evidence_collect → audit_report_generate.
5. **Supply chain before trusting third-party agent code:** scan_mcp_plugin or scan_skill → vet_endpoint on any endpoint that code calls out to.

Every paid tool accepts an optional **previous_scan_id**. Pass the scan_id of the step you are building on to record lineage, so the whole chain is retrievable later via agent_scan_get. It must be one of your own scans; it does not change the analysis.

# Authorization and scope

vuln_scan_network and vuln_scan_web_app send real traffic to the target and can trip intrusion detection. Only run them against hosts the user owns or is explicitly authorized to test, and confirm that before the call. Everything else here is passive (public DNS, certificates, threat-intel feeds, code the user supplied) and safe against any target.

Private, reserved and loopback addresses are rejected by design. Repository scans accept https URLs only.

# Results and errors

- Both scanners can run asynchronously: pass async: true (some deployments default to it) and you get a job_id instead of findings. Poll GET /v1/jobs/{job_id} with the API key rather than re-calling the tool, which would charge again.
- HTTP 402 means no valid payment was attached. Either supply an API key or complete the x402 challenge; do not retry the same unpaid request.
- A tool returning {"error": ...} has already been billed on the x402 rail. Surface the error, do not silently retry.
- Verdicts are advisory. PROCEED is not a guarantee, and reputation feeds false-positive on large CDN and cloud infrastructure. Present findings as evidence for the user's decision, not as certainty.`;
}

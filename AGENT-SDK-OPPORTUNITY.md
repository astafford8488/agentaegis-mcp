# AgentAegis + Claude Agent SDK — Security Audit Agent Product

**Date:** 2026-05-21
**Status:** Backlog proposal — new product tier, evaluate after Phase 8 launch

---

## TL;DR

Build an autonomous **Security Audit Agent** that connects to AgentAegis's MCP tools and runs comprehensive security assessments without human intervention. Instead of customers calling individual tools at $0.10-1.00 each, they pay $50-200 for a complete audit. This is a new product layer on top of the existing per-tool MCP server — higher margin, higher value, lower friction for customers who don't know which tools to run.

---

## The Problem This Solves

Current AgentAegis model: customer's AI agent calls individual MCP tools. This requires the customer to:
1. Know which tools exist (21 tools across 7 categories)
2. Know what order to run them in
3. Know how to interpret results and chain follow-up calls
4. Build their own orchestration logic

Most potential customers (especially non-security-specialists using AI agents) don't know any of this. They want: "tell me if my stuff is secure."

---

## The Product: Managed Security Audit Agent

A Claude Managed Agent, hosted on Anthropic infrastructure, that:

1. **Takes minimal input** — a domain, IP, repo URL, or cloud config
2. **Autonomously decides which tools to run** based on what it discovers
3. **Chains results intelligently** — e.g., port scan reveals open 443 → triggers SSL audit → finds weak cipher → flags in report
4. **Produces a structured report** — executive summary, findings by severity, remediation steps, compliance mapping
5. **Runs in a sandboxed environment** — customer data never touches your infrastructure (Anthropic's gVisor containers)

### How It Works (Technical)

```
Customer API call
  → Anthropic Managed Agents API (creates session)
    → Agent spawns with system prompt + AgentAegis MCP config
      → Agent calls AgentAegis MCP tools autonomously:
          network_port_scan → ssl_certificate_audit → dns_security_check
          → vulnerability_scan → email_security_audit → ...
      → Agent synthesizes findings into structured report
    → Session completes, report returned via API
  → Customer receives audit report (JSON + markdown)
```

### Architecture

```
agentaegis-mcp/
  src/
    audit-agent/
      agent-config.ts      # Managed Agent session config
      system-prompt.ts      # Security audit methodology prompt
      report-template.ts    # Structured output format
      api-endpoint.ts       # POST /v1/audit — creates agent session
      webhook-handler.ts    # Receives completed audit via callback
      pricing.ts            # Audit tier definitions + billing
  tests/
    audit-agent/
      integration.test.ts   # End-to-end audit against test targets
      report-quality.test.ts # Report completeness + accuracy checks
```

### The Agent's System Prompt (sketch)

```
You are a senior cybersecurity auditor. You have access to AgentAegis
security tools via MCP. Your job is to perform a comprehensive security
assessment of the target provided.

Methodology:
1. RECONNAISSANCE — Identify the attack surface (ports, services, DNS, SSL)
2. VULNERABILITY ASSESSMENT — Scan for known CVEs, misconfigurations
3. COMPLIANCE CHECK — Map findings against requested framework (ISO 27001,
   HIPAA, SOC 2, PCI DSS, NIST CSF)
4. THREAT INTELLIGENCE — Check IPs/domains against threat feeds
5. REPORT — Produce structured findings with severity, evidence, remediation

Rules:
- Never perform destructive actions (no exploitation, no DoS)
- If a tool fails, note it and continue with remaining tools
- Always provide remediation steps, not just findings
- Map every finding to at least one compliance control
```

---

## Pricing Model

### Per-Audit Tiers

| Tier | Scope | Tools Used | Price | Est. Cost | Margin |
|---|---|---|---|---|---|
| **Quick Scan** | Domain/IP only — ports, SSL, DNS, threat intel | 5-7 tools | $49 | ~$5-8 (tokens + tools + session) | ~85% |
| **Standard Audit** | Full external assessment + compliance mapping | 12-15 tools | $149 | ~$15-25 | ~85% |
| **Deep Audit** | External + code repo + cloud config + all frameworks | 18-21 tools | $299 | ~$30-50 | ~85% |

### Cost Breakdown (Standard Audit example)

| Component | Cost |
|---|---|
| Claude Opus tokens (~50K input, ~10K output) | ~$3.50 |
| Managed Agent session runtime (~15 min = 0.25 hr) | ~$0.02 |
| AgentAegis tool calls (12 tools @ avg $0.30) | ~$3.60 |
| External API costs (NVD, AbuseIPDB, etc.) | ~$0.50 |
| **Total cost per audit** | **~$7.62** |
| **Customer pays** | **$149** |
| **Gross margin** | **~95%** |

### Comparison to Current Model

| Metric | Per-Tool (current) | Audit Agent (proposed) |
|---|---|---|
| Avg revenue per customer session | $1-5 | $49-299 |
| Customer effort | High (must orchestrate) | Zero (submit target, get report) |
| Addressable market | AI agent developers only | Anyone who needs a security assessment |
| Recurring potential | Depends on customer's agent usage | Monthly/quarterly scheduled audits |

---

## Implementation Plan

### Phase A — Proof of Concept (~2 days)

- [ ] **A.1** — Write the audit agent system prompt (methodology, tool selection logic, report format)
- [ ] **A.2** — Test locally with Agent SDK against a test target (e.g., agentaegis.org itself)
- [ ] **A.3** — Validate: does the agent choose reasonable tools? Does it chain results? Is the report useful?
- [ ] **A.4** — Measure: token cost, session duration, tool call count, report quality

### Phase B — API Endpoint (~2-3 days)

- [ ] **B.1** — `POST /v1/audit` endpoint — accepts `{target, scope, framework, callback_url}`
- [ ] **B.2** — Creates Managed Agent session via Anthropic API (requires `managed-agents-2026-04-01` beta header)
- [ ] **B.3** — Agent connects to AgentAegis MCP (same Railway URL, uses a dedicated internal API key)
- [ ] **B.4** — Webhook handler receives completed audit, stores report in Supabase
- [ ] **B.5** — `GET /v1/audit/:id` — retrieve completed report (JSON + rendered markdown)
- [ ] **B.6** — Billing: deduct audit price from customer balance (or Stripe checkout for one-off)

### Phase C — Portal Integration (~1-2 days)

- [ ] **C.1** — `/audits` page in agentaegis-portal — list past audits, view reports
- [ ] **C.2** — "Run New Audit" wizard — pick target, scope, framework → submit
- [ ] **C.3** — Real-time status while audit runs (polling session status)
- [ ] **C.4** — PDF export of audit report

### Phase D — Launch (~1 day)

- [ ] **D.1** — Pricing page update on agentaegis.org
- [ ] **D.2** — Demo audit in the launch video (Phase 8 demo video — "watch AgentAegis audit itself")
- [ ] **D.3** — Show HN angle: "I built an AI security auditor that runs autonomously"

---

## Where This Fits in the Roadmap

**Sequence:** Phase 8 (launch prep) → **Phase 9: Audit Agent** → Phase 10+ (cloud integrations, etc.)

Or: run Phase A (PoC) in parallel with Phase 8. If the PoC validates, the audit agent becomes THE demo in the launch video. "Watch an AI agent autonomously audit a live server in 10 minutes" is a much stronger Show HN than "here's an MCP server with 21 tools."

---

## Risks & Open Questions

| Risk | Mitigation |
|---|---|
| Managed Agents API is still beta (April 2026) | Phase A uses local Agent SDK first. Switch to Managed Agents when GA. |
| Agent might call tools in suboptimal order | System prompt enforces methodology. Log tool sequences for optimization. |
| Agent might hallucinate findings | Every finding must cite tool output. Report template enforces `evidence` field. |
| Long-running audits (30+ min) timeout | Set session timeout to 60 min. Break Deep Audits into sub-phases if needed. |
| Customers submit malicious targets (scan someone else's infra) | Require domain/IP ownership verification (DNS TXT record or HTTP meta tag). |
| Cost spikes from token-heavy reports | Cap report length. Use Sonnet for the agent loop, Opus only for synthesis. |

### Open Questions

- **Should audit agent have its own API key, or use customer's key?** Leaning: dedicated internal key with separate budget, so tool costs are included in audit price (not double-charged).
- **Scheduled audits?** Monthly recurring audits at a discount ($99/mo for Standard) would be strong recurring revenue. Add after Phase C.
- **White-label?** MSSPs could resell audit reports under their own brand. Table for Phase 10+.

---

## Patent Implications

The provisional patent (App. No. 64/057,021) covers the dual-rail payment architecture and MCP-aware body-inspection gating. An autonomous audit agent that uses this payment infrastructure to run tool calls and bills the customer a flat rate may strengthen the patent's commercial value for the nonprovisional filing. **Flag for patent attorney review before 2027-05-04 deadline.**

---

## Resources

- [Managed Agents overview](https://platform.claude.com/docs/en/managed-agents/overview)
- [Agent SDK overview](https://code.claude.com/docs/en/agent-sdk/overview)
- [MCP in the SDK](https://docs.claude.com/en/docs/agent-sdk/mcp)
- [Managed Agents pricing](https://wavespeed.ai/blog/posts/claude-managed-agents-pricing-2026/)
- SDK: `pip install claude-agent-sdk` / `npm install @anthropic-ai/claude-agent-sdk`
- Managed Agents API: requires `managed-agents-2026-04-01` beta header

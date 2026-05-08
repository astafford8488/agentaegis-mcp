# NOTICE

AgentAegis is a hosted MCP server that wraps multiple open-source security tools and third-party threat-intelligence APIs behind a unified per-call billing layer. This file acknowledges and attributes the projects we depend on.

The integration layer, dual-rail payment architecture (API key + x402), body-inspection gating, unified usage logging, customer portal, and patent-pending orchestration are AgentAegis-proprietary. Everything below is third-party software or data.

---

## Open-source scanning engines we wrap

We invoke these as subprocesses (CLI commands), parse their stdout, and return normalized JSON. We do not modify or redistribute their source code.

| Project | License | Used by tool | Project URL |
|---|---|---|---|
| **nmap** | GPLv2 | `vuln_scan_network` | https://nmap.org |
| **Nuclei** (ProjectDiscovery) | MIT | `vuln_scan_web_app` | https://github.com/projectdiscovery/nuclei |
| **sslyze** (Nabla-C0d3) | AGPL-3.0 | `ssl_tls_audit` | https://github.com/nabla-c0d3/sslyze |
| **Semgrep CE** (Semgrep Inc.) | LGPL-2.1 | `sast_scan` | https://semgrep.dev |
| **trufflehog** (Truffle Security) | AGPL-3.0 | `secret_scan` | https://github.com/trufflesecurity/trufflehog |
| **trivy** (Aqua Security) | Apache-2.0 | `dependency_audit` | https://aquasecurity.github.io/trivy |

### AGPL compliance posture

Two of the engines above (`sslyze`, `trufflehog`) are licensed under the GNU AGPL-3.0. AGPL requires that if you distribute the software OR offer it as a service over a network, you must also offer the source code of any modifications.

AgentAegis's usage pattern: we exec these tools as separate subprocess invocations using their public CLI surface and parse their stdout. We do NOT modify, link against, or redistribute their source code. The standard FSF and community interpretation is that subprocess invocation does NOT trigger AGPL "linking" requirements — we are using the program, not creating a derivative work.

If you are an upstream maintainer of `sslyze` or `trufflehog` and want a different attribution, additional acknowledgment, or have a license-compliance concern, please email admin@youraigroup.com and we will respond within 5 business days.

## Threat intelligence + data sources

We call these APIs and include their data in tool responses. We hold the relevant API keys, license, or comply with the public ToS.

| Source | Coverage | Used by tool | License / Terms |
|---|---|---|---|
| **NVD** (NIST National Vulnerability Database) | CVE catalog + CVSS | `cve_lookup`, `vuln_prioritize` | Public domain (US Government) |
| **AbuseIPDB** | IP reputation | `threat_intel_lookup` | Commercial API key |
| **AlienVault OTX** (AT&T) | Threat indicators | `threat_intel_lookup` | Free tier, commercial OK |
| **abuse.ch** (URLhaus, Feodo Tracker, etc.) | Malware/botnet IOCs | `threat_intel_lookup` | Free, commercial OK |
| **Have I Been Pwned (HIBP)** (Troy Hunt) | Breach data | `credential_check` | Commercial API key ($3.50/mo) |
| **Shodan** (planned) | Internet-facing asset metadata | (planned) | Commercial API key |

## Compliance frameworks (standards we map to)

These are public standards published by their respective bodies. We map controls and generate evidence/policies against them; we do not redistribute the framework documents themselves.

- **SOC 2** — AICPA (American Institute of Certified Public Accountants)
- **ISO/IEC 27001:2022** — ISO/IEC
- **HIPAA Security Rule** — US HHS
- **PCI DSS v4.0** — PCI Security Standards Council
- **NIST Cybersecurity Framework (CSF)** — NIST

## Cryptocurrency / payment infrastructure

| Component | Provider | License / Terms |
|---|---|---|
| **x402 protocol** | x402.org reference implementation + community | Open source (per x402.org) |
| **x402 facilitator** | https://x402.org/facilitator | Public reference facilitator |
| **viem** (Ethereum signing library) | Wagmi/wevm | MIT |
| **x402-fetch** + **x402-express** (npm packages) | x402 community | MIT |
| **USDC stablecoin** (Base mainnet, Ethereum) | Circle Internet Financial | ERC-20 / ERC-3009 |
| **Base** (L2 network) | Base / Coinbase | Public blockchain |

## Other infrastructure dependencies

| Component | Provider | Role |
|---|---|---|
| **Node.js** | OpenJS Foundation | Runtime |
| **Express** | OpenJS Foundation | HTTP framework (MIT) |
| **Model Context Protocol SDK** | Anthropic PBC | MCP transport (MIT) |
| **Supabase** | Supabase Inc. | Postgres + auth (commercial) |
| **Stripe** | Stripe Inc. | Payment processing (commercial) |
| **Railway** | Railway Corp. | MCP server hosting (commercial) |
| **Vercel** | Vercel Inc. | Portal + marketing site hosting (commercial) |
| **Sentry** | Functional Software Inc. | Error tracking (commercial, free tier) |
| **Better Stack** | Better Stack | Uptime monitoring + status page (commercial, free tier) |
| **Cloudflare** | Cloudflare Inc. | DNS, CDN (commercial) |

## Reporting issues with this NOTICE

If anything in this file is inaccurate, missing, or you believe AgentAegis is using your project in a way that violates your license, please email admin@youraigroup.com. We will respond within 5 business days and take corrective action where appropriate.

Last updated: 2026-05-07

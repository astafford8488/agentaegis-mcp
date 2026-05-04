# AgentAegis MCP Server

Every cybersecurity service, callable by any AI agent, billed per use.

AgentAegis is an MCP server that lets AI agents perform cybersecurity operations on demand — from compliance checks to vulnerability scans to code security analysis. It wraps best-in-class open-source scanning engines (nmap, Nuclei, sslyze, Semgrep, trufflehog, trivy) in clean, agent-discoverable tool definitions with structured inputs and outputs.

**Phase 2 ships:** HTTP transport for remote deployment, x402 micropayments, API key auth with monthly limits, Supabase persistence, webhooks, ISO 27001 + HIPAA frameworks, Railway deploy config, and a full test suite.

## Quick Start

### Local (stdio for Claude Desktop)

```bash
git clone https://github.com/astafford8488/agentaegis-mcp.git
cd agentaegis-mcp
pnpm install
cp .env.example .env  # add API keys
pnpm build
```

Add to `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "agentaegis": {
      "command": "node",
      "args": ["/path/to/agentaegis-mcp/dist/index.js"],
      "env": {
        "NVD_API_KEY": "...",
        "ABUSEIPDB_API_KEY": "...",
        "OTX_API_KEY": "...",
        "ABUSECH_API_KEY": "...",
        "HIBP_API_KEY": "..."
      }
    }
  }
}
```

### Remote (HTTP, for agent platforms)

```bash
# Local dev
pnpm dev:http

# Production via Docker
docker compose -f docker/docker-compose.yml up -d

# Production via Railway
railway up
```

Connect from any MCP-aware agent:
```
POST https://your-host/mcp
Authorization: Bearer aegis_<your-api-key>
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│         AI Agent (Claude, custom MCP client)            │
└────────────────┬───────────────────────┬─────────────────┘
                 │ stdio                 │ HTTP
                 │                       │
┌────────────────▼───────────┐  ┌────────▼─────────────────┐
│   stdio entry (index.ts)   │  │  HTTP entry (http-server)│
└────────────────┬───────────┘  └────────┬─────────────────┘
                 │                       │
                 │      ┌────────────────┴─────────────┐
                 │      │  Auth Gate                   │
                 │      │  - API key (DB-backed)       │
                 │      │  - x402 micropayment         │
                 │      └─────────────┬────────────────┘
                 │                    │
┌────────────────▼────────────────────▼──────────────────────┐
│              MCP Server (server.ts)                          │
│              20 Tool Handlers                                │
├──────────────────────────┬────────────────────────────────┤
│  Engine Wrappers         │  External APIs                  │
│  nmap, Nuclei, sslyze,   │  NVD, AbuseIPDB, AlienVault OTX + abuse.ch,    │
│  Semgrep, trufflehog,    │  HIBP, Shodan                   │
│  trivy                   │                                  │
├──────────────────────────┴────────────────────────────────┤
│  Sandbox    │ Rate Limit │ Target Validation │ Logging     │
└────────────────────────────────────────────────────────────┘
                            │
                  ┌─────────▼──────────┐
                  │  Supabase          │
                  │  - customers       │
                  │  - api_keys        │
                  │  - scan_jobs       │
                  │  - usage_log       │
                  │  - webhooks        │
                  └────────────────────┘
```

## HTTP API (Phase 2)

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/health` | GET | None | Health check |
| `/pricing` | GET | None | Tool catalog with prices |
| `/v1/customers` | POST | None | Create customer account |
| `/v1/customers/:id/api-keys` | POST | None | Issue an API key |
| `/v1/customers/:id/usage` | GET | API key | Usage statistics |
| `/v1/jobs/:jobId` | GET | API key | Async scan job status |
| `/mcp` | POST | API key OR x402 | MCP Streamable HTTP transport |

### Payment Flow

**Option 1: API Key** — Customer registers, gets a key, pays via prepaid balance or invoice. Each tool call deducts from the monthly budget.

```bash
curl -X POST https://api.agentaegis.org/v1/customers \
  -H "Content-Type: application/json" \
  -d '{"email":"you@company.com","name":"Your Name"}'

curl -X POST https://api.agentaegis.org/v1/customers/<id>/api-keys \
  -H "Content-Type: application/json" \
  -d '{"name":"production","monthly_limit_usd":100}'
```

**Option 2: x402 Micropayment** — No signup. Each tool call settles on-chain via USDC. The server returns `402 Payment Required` with payment requirements; the client signs and retries with `X-PAYMENT` header.

## Tool Catalog (20 tools)

| Tool | Category | Description | Price |
|------|----------|-------------|-------|
| `compliance_framework_check` | Compliance | SOC 2, ISO 27001, HIPAA, PCI-DSS, NIST CSF assessment | $0.50 |
| `evidence_collect` | Compliance | Evidence collection plans for audit controls | $0.25 |
| `control_gap_analysis` | Compliance | Prioritized remediation roadmap | $0.50 |
| `audit_report_generate` | Compliance | Audit-ready compliance reports | $1.00 |
| `policy_generate` | Compliance | Tailored security policy documents | $0.50 |
| `vuln_scan_network` | Vuln Mgmt | Network port and vulnerability scan | $1.00 |
| `vuln_scan_web_app` | Vuln Mgmt | OWASP Top 10 web app scan | $1.50 |
| `vuln_prioritize` | Vuln Mgmt | Risk-based vulnerability prioritization | $0.25 |
| `cve_lookup` | Vuln Mgmt | CVE details, CVSS, KEV status | $0.10 |
| `ssl_tls_audit` | Vuln Mgmt | SSL/TLS configuration audit | $0.25 |
| `sast_scan` | Code Security | Static security analysis | $1.00 |
| `secret_scan` | Code Security | Hardcoded secret detection | $0.50 |
| `dependency_audit` | Code Security | Dependency vulnerability scan | $0.50 |
| `incident_triage` | Blue Team | Incident classification & response plan | $0.75 |
| `threat_intel_lookup` | Blue Team | IOC reputation lookup | $0.25 |
| `dns_security_check` | Blue Team | DNS security audit | $0.25 |
| `email_security_audit` | Blue Team | Email security configuration audit | $0.50 |
| `access_review` | Identity | Access privilege audit | $0.50 |
| `mfa_audit` | Identity | MFA coverage assessment | $0.25 |
| `credential_check` | Offensive | Breach database lookup | $0.50 |

## Compliance Frameworks Supported

- **SOC 2 Type II** — Full Trust Services Criteria (35 controls)
- **ISO 27001:2022** — All 4 Annex A control groups (93 controls)
- **HIPAA Security Rule** — Administrative, physical, and technical safeguards (43 controls)
- **NIST CSF 2.0** — All 6 functions with categories
- **PCI DSS v4.0** — All 12 requirements with detailed controls (full evaluation logic)

## Development

```bash
pnpm install        # Install dependencies
pnpm dev            # stdio mode (for Claude Desktop)
pnpm dev:http       # HTTP mode (with Streamable HTTP transport)
pnpm build          # Build for production
pnpm test           # Run vitest test suite (46 tests)
```

## Deployment

### Railway (Recommended)

```bash
railway login
railway init
railway up
```

Required env vars (set in Railway dashboard):
- `SUPABASE_URL`, `SUPABASE_SERVICE_KEY`
- `X402_PAYEE_ADDRESS` (your wallet)
- `NVD_API_KEY`, `ABUSEIPDB_API_KEY`, `OTX_API_KEY`, `ABUSECH_API_KEY`, `HIBP_API_KEY`

### Database setup

Run the migration in your Supabase SQL editor:
```bash
cat supabase/migrations/001_initial_schema.sql
```

## Security Policy

- **Target validation**: Only public IPs and registered domains. Private/reserved ranges blocked.
- **Scan isolation**: Each scan runs in an isolated process with temp directory cleanup.
- **Code safety**: Repos cloned shallow (depth=1), max 500MB, 5-minute timeout, no execution.
- **Secret redaction**: Full secret values never returned — first 4 and last 4 characters only.
- **Rate limiting**: Per API key AND per target. Max 5 concurrent scans, 10/hour per target.
- **Audit logging**: All tool calls logged to `usage_log` (90-day retention).
- **API key hashing**: Keys stored as SHA-256 hashes; raw keys never stored.

## Responsible Use

AgentAegis scanning tools must only be used against systems you own or have explicit written authorization to test. By using this service, you agree that:

1. You have authorization from the system owner to perform security testing
2. You will not use these tools for unauthorized access or malicious purposes
3. You accept responsibility for any scans initiated through your API key

## License

MIT

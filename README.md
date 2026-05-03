# AgentAegis MCP Server

Every cybersecurity service, callable by any AI agent, billed per use.

AgentAegis is an MCP server that lets AI agents perform cybersecurity operations on demand — from compliance checks to vulnerability scans to code security analysis. It wraps best-in-class open-source scanning engines (nmap, Nuclei, sslyze, Semgrep, trufflehog, trivy) in clean, agent-discoverable tool definitions with structured inputs and outputs, metered via x402 micropayments.

## Quick Start

### Prerequisites

- Docker and Docker Compose
- API keys (optional, but enables full functionality):
  - NVD API key (free): https://nvd.nist.gov/developers/request-an-api-key
  - AbuseIPDB (free tier): https://www.abuseipdb.com/account/api
  - VirusTotal (free tier): https://www.virustotal.com/gui/join-us
  - Have I Been Pwned ($3.50/mo): https://haveibeenpwned.com/API/Key

### Run with Docker

```bash
git clone https://github.com/yourusername/agentaegis-mcp.git
cd agentaegis-mcp

# Configure environment
cp .env.example .env
# Edit .env with your API keys

# Start
docker compose -f docker/docker-compose.yml up -d
```

### Run Locally (Development)

```bash
pnpm install
pnpm dev
```

### Connect to Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "agentaegis": {
      "command": "node",
      "args": ["path/to/agentaegis-mcp/dist/index.js"],
      "env": {
        "NVD_API_KEY": "your-key",
        "ABUSEIPDB_API_KEY": "your-key",
        "VIRUSTOTAL_API_KEY": "your-key",
        "HIBP_API_KEY": "your-key"
      }
    }
  }
}
```

## Tool Catalog (19 tools)

| Tool | Category | Description | Price |
|------|----------|-------------|-------|
| `compliance_framework_check` | Compliance | Assess posture against SOC 2, ISO 27001, HIPAA, PCI-DSS, NIST CSF | $0.50 |
| `evidence_collect` | Compliance | Generate evidence collection plans for audit controls | $0.25 |
| `control_gap_analysis` | Compliance | Prioritized remediation roadmap for compliance gaps | $0.50 |
| `audit_report_generate` | Compliance | Generate audit-ready compliance reports | $1.00 |
| `policy_generate` | Compliance | Generate tailored security policy documents | $0.50 |
| `vuln_scan_network` | Vuln Mgmt | Scan IPs/domains for open ports and vulnerabilities | $1.00 |
| `vuln_scan_web_app` | Vuln Mgmt | Scan web apps for OWASP Top 10 vulnerabilities | $1.50 |
| `vuln_prioritize` | Vuln Mgmt | Prioritize findings by exploitability and business impact | $0.25 |
| `cve_lookup` | Vuln Mgmt | Look up CVE details, CVSS, patches, KEV status | $0.10 |
| `ssl_tls_audit` | Vuln Mgmt | Audit SSL/TLS config — certs, protocols, ciphers | $0.25 |
| `sast_scan` | Code Security | Static analysis for security vulnerabilities | $1.00 |
| `secret_scan` | Code Security | Detect hardcoded secrets in source code | $0.50 |
| `dependency_audit` | Code Security | Audit dependencies for known vulnerabilities | $0.50 |
| `incident_triage` | Blue Team | Classify and respond to security incidents | $0.75 |
| `threat_intel_lookup` | Blue Team | IOC lookup against threat intelligence feeds | $0.25 |
| `dns_security_check` | Blue Team | Check DNS security (SPF, DKIM, DMARC, DNSSEC) | $0.25 |
| `email_security_audit` | Blue Team | Comprehensive email security audit | $0.50 |
| `access_review` | Identity | Audit user access against least-privilege | $0.50 |
| `mfa_audit` | Identity | Assess MFA coverage and strength | $0.25 |
| `credential_check` | Offensive | Check emails/domains in breach databases | $0.50 |

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    AI Agent (Claude, etc.)                │
└────────────────────────────┬────────────────────────────┘
                             │ MCP Protocol (stdio)
┌────────────────────────────▼────────────────────────────┐
│                  AgentAegis MCP Server                    │
├──────────────┬──────────────┬───────────────────────────┤
│  x402 Payment│  Rate Limiter │  Input Sanitizer          │
│  Middleware  │              │  & Target Validator        │
├──────────────┴──────────────┴───────────────────────────┤
│                    19 Tool Handlers                       │
├─────────────────────────────────────────────────────────┤
│  Engine Wrappers          │  External API Clients        │
│  ├── nmap                 │  ├── NVD (CVE)              │
│  ├── Nuclei               │  ├── AbuseIPDB             │
│  ├── sslyze               │  ├── VirusTotal            │
│  ├── Semgrep              │  ├── HIBP                  │
│  ├── trufflehog           │  └── Shodan                │
│  └── trivy                │                             │
├─────────────────────────────────────────────────────────┤
│  Sandboxed Execution    │  Job Queue  │  Scan Logging   │
└─────────────────────────────────────────────────────────┘
```

## Security Policy

- **Target validation**: Only public IPs and registered domains. Private/reserved ranges blocked.
- **Scan isolation**: Each scan runs in an isolated process with temp directory cleanup.
- **Code safety**: Repos cloned shallow (depth=1), max 500MB, 5-minute timeout, no execution.
- **Secret redaction**: Full secret values never returned — first 4 and last 4 characters only.
- **Rate limiting**: Per API key AND per target. Max 5 concurrent scans, 10/hour per target.
- **Audit logging**: All scan targets logged for abuse investigation (90-day retention).

## Responsible Use

AgentAegis scanning tools must only be used against systems you own or have explicit written authorization to test. By using this service, you agree that:

1. You have authorization from the system owner to perform security testing
2. You will not use these tools for unauthorized access or malicious purposes
3. You accept responsibility for any scans initiated through your API key

## Development

```bash
pnpm install        # Install dependencies
pnpm dev            # Start in dev mode (hot reload)
pnpm build          # Build for production
pnpm test           # Run tests
```

## License

MIT

# Red Team Test Suite

Automated and manual attack execution for AgentAegis.

**Plan document:** `../RED_TEAM_PLAN.md`
**Findings:** `../RED_TEAM_REPORT.md` (generated as we run)

## Layout

```
red-team/
├── README.md              ← you are here
├── auto/                  ← auto-runnable tests (TypeScript via tsx)
│   ├── b1-balance-race.ts
│   ├── b3-stolen-key-blast.ts
│   ├── b5-cross-customer.ts
│   ├── d1-d4-mcp-bypass.ts
│   ├── d5-session-id-entropy.ts
│   ├── e1-e3-webhook-ssrf.ts
│   ├── f1-f2-open-redirect.ts
│   ├── g1-g3-rls.ts
│   ├── h1-subdomain-takeover.sh
│   └── h4-stripe-webhook-spoof.ts
├── manual/                ← manual procedures (markdown runbooks)
│   ├── a1-replay-attack.md
│   ├── a2-signature-substitution.md
│   ├── a3-balance-race-x402.md
│   ├── a4-settlement-double-claim.md
│   ├── a5-frontrun.md
│   └── f3-pkce-downgrade.md
├── gated/                 ← can DoS production; require --allow-dos flag
│   ├── c1-free-tool-flood.ts
│   ├── c2-faq-flood.ts
│   ├── c3-mcp-session-flood.ts
│   ├── c4-slowloris.ts
│   └── h3-waf-probes.ts
└── results/               ← per-run JSON outputs
    └── YYYY-MM-DD-<test-id>.json
```

## Running

### Prerequisites

```bash
# Install dependencies for the auto tests
cd /path/to/agentaegis-mcp
pnpm install
# Auto tests use tsx + node:fetch; no extra deps beyond the main repo

# For subdomain scan (h1):
brew install subjack    # macOS
# or
go install github.com/haccer/subjack@latest

# For Cloudflare WAF probe (h3, gated):
brew install nikto       # or use Burp Suite manually
```

### Environment variables

Copy `.env.red-team.example` to `.env.red-team` and fill in:

```bash
# Production endpoint to test against
TARGET_BASE_URL=https://agentaegis-mcp-production.up.railway.app

# Test customer with a SMALL balance ($0.20–$1.00 max so we don't drain real customers)
RED_TEAM_API_KEY=aegis_<test-only-key>
RED_TEAM_CUSTOMER_ID=<test-customer-uuid>

# Cross-customer test fixture (a SECOND test customer's id, used to verify RLS)
RED_TEAM_OTHER_CUSTOMER_ID=<other-test-customer-uuid>

# Anon Supabase key for RLS test (publicly safe — same as portal uses)
SUPABASE_URL=https://thtnfctijtpdoplyftaw.supabase.co
SUPABASE_ANON_KEY=sb_publishable_...
```

⚠️ **DO NOT** put real production API keys with non-test customers' balances in `.env.red-team`. The B-series tests will deliberately try to drain a balance to verify the cap. Use a dedicated test customer.

### Run all auto tests

```bash
pnpm tsx audit/red-team/run-all.ts
# or for one specific test
pnpm tsx audit/red-team/auto/b1-balance-race.ts
```

### Run gated (DoS) tests

These can saturate the production endpoint. Only run on a quiet day with Andrew's go-ahead:

```bash
pnpm tsx audit/red-team/gated/c1-free-tool-flood.ts --allow-dos --duration=60s --rps=200
```

The `--allow-dos` flag is REQUIRED. Tests refuse to run without it.

### Manual procedures

Open the relevant `manual/<id>.md` and follow the runbook. Each ends with a "what to record" section that produces a JSON file matching the auto-test output format, so findings are uniform.

## Reporting

After all tests are done, append findings to `../RED_TEAM_REPORT.md`. Each finding follows the template in the plan. Severity-tag accordingly. Mitigation work goes into separate commits referencing the finding ID.

## Continuous integration

The auto suite (no DoS, no manual) runs in CI weekly via GitHub Actions:

```yaml
# .github/workflows/red-team-auto.yml — to be created in Phase 9
- cron: "0 6 * * 1"  # Mondays at 06:00 UTC
- run: pnpm tsx audit/red-team/run-all.ts --output=results/$(date +%F)-ci.json
- uses: actions/upload-artifact@v4
  with:
    name: red-team-results
    path: audit/red-team/results/
```

This catches regressions when a future commit accidentally weakens a control.

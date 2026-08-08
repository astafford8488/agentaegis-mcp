# AGENTS.md — working in this repository

Guidance for AI coding agents (Claude Code, Codex, Cursor, Copilot) making changes to `agentaegis-mcp`.

If you are an agent looking to **use** AgentAegis rather than modify it, you do not need this file. Connect to the MCP server and read the server `instructions` and the `help` tool, or see `skills/agentaegis-security/SKILL.md`.

---

## What this is

A hosted MCP server that sells cybersecurity scans to AI agents, per call, on two payment rails: a prepaid API-key balance, and per-call USDC settled on Base mainnet via x402.

**This process handles real money.** A bug in the billing path either charges callers for nothing or gives away paid scans. Treat `src/transport/httpServer.ts`, `src/auth/`, `src/payments/` and `wrapTool` in `src/server.ts` as money-path code: read the surrounding logic before changing it, and say what you changed in the PR or commit body.

`master` auto-deploys to Railway production. There is no staging environment.

---

## Commands

```bash
npm run build     # tsc — must pass before any commit
npm test          # vitest run — 138 tests, must stay green
npm run lint      # eslint src/
npm run dev:http  # local HTTP transport with watch
```

`semgrep` and the other scanner binaries are not installed on Windows dev machines. Tests that shell out to them log `spawn semgrep ENOENT` and fall back gracefully — that is expected locally and not a failure.

---

## Layout

| Path | What lives there |
|---|---|
| `src/server.ts` | Tool registration, `wrapTool` billing + scan persistence, server `instructions` |
| `src/instructions.ts` | The server-level guidance injected into every connecting client's system prompt |
| `src/prompts.ts` | MCP prompts — guided multi-tool workflows |
| `src/transport/httpServer.ts` | Streamable HTTP transport **and the live x402 gate** |
| `src/transport/httpResource.ts` | Standalone HTTP x402 resources (the CDP Bazaar listing path) |
| `src/tools/` | One file per tool, grouped by category |
| `src/tools/trustLayer/` | L2 composite verdict tools — the flagship and patent subject |
| `src/engines/` | Subprocess wrappers: nmap, Nuclei, sslyze, Semgrep, trufflehog, trivy |
| `src/types/mcp.ts` | `TOOL_PRICING` — the single source of truth for what a call costs |
| `audit/x402-test/` | Payment bootstrap scripts. **See the warning below.** |

---

## Invariants — break these and something bills wrong

**`TOOL_PRICING` is the only place a price is defined.** `wrapTool` reads it to decide free vs paid, the x402 gate reads it to build the payment challenge, and `src/instructions.ts` generates its catalog from it. Never hardcode a price anywhere else. Adding a tool without a `TOOL_PRICING` entry silently makes it free.

**Free tools must be priced `0` and registered with `server.tool(...)` + `wrapTool(name, fn, { skipPayment: true })`,** not `registerPaidTool`. Free tools bypass billing and scan persistence entirely.

**The live x402 gate is inline in `src/transport/httpServer.ts`,** not in `processX402Payment` (which is unused legacy). It charges only when `body.method === "tools/call"` and the tool has a nonzero price and no API key is present. Any other JSON-RPC method — `initialize`, `tools/list`, `prompts/list`, `prompts/get` — passes through free. Keep it that way: charging for discovery would break every client.

**x402 settles before the handler runs.** A tool that throws after settlement has already taken the caller's money. That is why `wrapTool` calls `updateUsageOutcome` to correct the usage row, and why `credential_check` only registers when `HIBP_API_KEY` is set — without it, callers would pay for an error. Apply the same reasoning to any new tool with a single unfallback-able upstream dependency.

**Repo-cloning tools must go through `cloneRepo`,** which enforces the SSRF guard in `validateGitUrl` (https only, no credentials, resolves and blocks private/reserved IPs including DNS rebinding). Never hand a caller-supplied URL to `git clone` directly.

**Input caps stay.** `code_snippet` and `skill_md` are capped at 2MB. These are pre-paid endpoints; unbounded input is a denial-of-wallet vector.

---

## Never do these

- **Do not run anything in `audit/x402-test/` that settles a payment.** `02-run-mainnet-payment.ts` and the `0*-bootstrap-*.ts` scripts move real USDC from a funded wallet on Base mainnet. They are Andrew's to run, deliberately, one at a time.
- **Do not commit secrets.** `cdp_api_key.json`, `wallets-mainnet.json` and `.env` are gitignored and must stay that way. The admin token, API keys and the CDP key belong in Windows Credential Manager, never in source, config, tests or commit messages. Inspect the staged diff before committing.
- **Do not put a real API key in `help.ts` or the docs.** A hardcoded example key leaked from there once and the whole customer account had to be deleted. Use `aegis_YOUR_API_KEY_HERE`.
- **Do not point active scanners at hosts you do not own.** `vuln_scan_network` and `vuln_scan_web_app` send real traffic. Sanctioned test targets only: `scanme.nmap.org`, `testphp.vulnweb.com`.
- **Do not add CAA records for `agentaegis.org`.** It is Cloudflare-fronted; a Let's Encrypt-only CAA would break certificate renewal. The old `ROADMAP.md` advice on this is wrong.

---

## Validating changes against production for $0

`POST /admin/dry-run {tool, args}` runs any analysis tool with **no billing, no x402, no scan persistence**, gated by the admin token. This is how you calibrate or verify a money-path tool on real production infrastructure without spending anything. Read the admin token from secure storage; never echo it into output, logs or commit messages.

Prefer this over test payments. Several tools only misbehave on the deployed container — Semgrep rule loading, the NVD datacenter-IP soft-block, and scanner timeouts were all invisible locally.

---

## Conventions

- ESM throughout. **Relative imports need the `.js` extension** even in TypeScript source.
- Zod schemas per tool, exported as `<toolName>Schema` alongside the handler.
- Tool handlers are pure-ish: they take parsed args and return a plain object. Billing, persistence and error shaping belong in `wrapTool`, not in the tool.
- Prefer extracting a pure scoring function (`scoreEndpoint`, `scoreSkill`, `scoreMcpPlugin`) and unit-testing it directly. Every verdict tool follows this pattern.
- Conventional commits (`feat:`, `fix:`, `docs:`, `chore:`) with a scope, matching existing history.

## Testing

Add tests to `tests/`. Behavioral tests over snapshot tests; for verdict tools include both a positive and a negative corpus, because the scorers have been retuned twice after a corpus exposed lenient scoring.

If you change pricing, tool names or the free/paid split, `tests/serverGuidance.test.ts` asserts the server instructions and prompt cost quotes against `TOOL_PRICING` and will fail on drift. Fix the source of truth, not the test.

# Demo video script — AgentAegis (3 min)

**Format:** screen recording + a separately-recorded voiceover (no talking head).
**Why this layout:** the voiceover is ONE continuous take (Section 1) so you record it start-to-finish in a single sitting and it flows naturally. The visuals (Section 2) and on-screen text (Section 3) are captured/added separately and synced to the VO timecodes in the edit.
**Tools:** OBS Studio or Loom (screen capture) · a decent mic for the VO · CapCut or DaVinci Resolve (edit).
**Output:** 1080p MP4, target 2:55 (±10s). Over 3:00 loses ~half the viewers; under 2:30 feels rushed. Upload Unlisted to YouTube; embed on agentaegis.org; link from Show HN + the X thread.

---

## 1. Voiceover — record in ONE continuous take

Read straight through, top to bottom, against the mic. The `[0:00]` markers are timing guides for the edit, **not** stops — only pause where you see **(beat)**. Flub a line? Re-read that sentence and keep rolling; trim the dead take in post. Record this AFTER the visuals (Section 4 explains why).

> `[0:00]` An AI agent just paid a dollar in stablecoin to scan a CVE on a public blockchain. No signup. No subscription. No support ticket. The whole transaction took three seconds. **(beat)**
>
> `[0:15]` AgentAegis is an MCP server — Model Context Protocol, the standard agents use to call tools — that lets your AI agent run twenty cybersecurity workflows: vulnerability scans, compliance checks, threat intel, code security, identity audits. The actual scanning is done by the open-source tools you already trust — nmap, Nuclei, Semgrep, sslyze, trufflehog, trivy. What we built is the integration layer that makes them callable from any MCP-compatible agent, plus the unified per-call billing. **(beat)** Two ways agents pay: a pre-funded API key with a monthly limit, the way most APIs work — or per call, in USDC, signed cryptographically and settled on-chain in three seconds, no account required. Both rails land on the same endpoint; the agent's MCP client doesn't change. Free tools work without payment, so agents can discover what's available before they spend anything. **(beat)**
>
> `[0:45]` Here's a paid call with an API key — same flow as any modern SaaS API. The agent calls cve_lookup for CVE-2024-3094, the XZ backdoor. The server checks the API key, confirms the balance covers the one-dollar price, does an atomic update on the customer record so two simultaneous calls can't over-draw, then runs the lookup against NVD. Nine seconds later the agent has CVSS, affected packages, references. The customer portal shows the charge — paid via API key, one dollar, balance now four dollars. **(beat)**
>
> `[1:30]` Now the autonomous version — no API key, no signup, no human in the loop. The agent posts to slash-m-c-p. The server returns four-oh-two: payment required. The agent signs an ERC-3009 transfer-with-authorization for one dollar of USDC — gasless, the agent doesn't even hold ETH. The server forwards the signed authorization to a facilitator, on-chain settlement completes, and the agent gets the tool result. Three seconds end-to-end on Base mainnet. Same usage log, same audit trail — the portal shows it side by side with the API-key call: same schema, different payment rail, an on-chain transaction hash you can verify on BaseScan right now. **(beat)**
>
> `[2:15]` Sign-up takes about two minutes. Top up at agentaegis dot org slash pay — five-dollar minimum, Stripe handles the card — and an email arrives with your first API key. The customer portal is at app dot agentaegis dot org: Google sign-in or a magic link, issue more keys, view usage, configure webhooks, export to CSV. Standard SaaS — except the underlying primitive is per-call billing instead of subscriptions. **(beat)**
>
> `[2:45]` agentaegis dot org. Twenty tools. Pay per call. No subscriptions. No human in the loop required. Patent pending on the architecture, built solo. Try it on your agent today.

**Length check:** ~2:55 at a calm pace. If you run long, the `[0:15]` product paragraph is the safest to trim.

---

## 2. Visual track — capture separately, sync to the VO timecodes

Record each as its own silent clip; drop it under the matching VO timecode in the edit.

- **`[0:00–0:15]` Cold open** — split screen: left, the Claude Desktop conversation; right, the AgentAegis MCP server logs streaming live.
- **`[0:15–0:45]` What it is** — agentaegis.org hero, then quick cuts: the `/pricing` table, the 20-tool list grouped by category, the `/faq` pricing snippet.
- **`[0:45–1:30]` Demo 1 — API key** — Claude Desktop pointed at the production `/mcp` with the demo key. In order: (1) the config showing the server URL + `Authorization: Bearer aegis_…`; (2) prompt "Look up CVE-2024-3094"; (3) the `cve_lookup` call appearing in the right-side logs; (4) the response (CVSS, packages, refs); (5) portal balance dropping $5.00 → $4.00; (6) `/account/usage` row showing `paid_via: api_key_balance`.
- **`[1:30–2:15]` Demo 2 — x402** — terminal running the x402 client. In order: (1) the script (POSTs to `/mcp`, no auth header); (2) run it → HTTP 402 with payment requirements (highlight `payTo`, `amount`); (3) the ERC-3009 signing log line; (4) the retry carrying the payment header; (5) BaseScan showing the on-chain $1 USDC transfer to `0x3347…F7fC`; (6) the tool result in stdout; (7) `/account/usage` row with `paid_via: x402` and the tx-hash `payment_ref`.
- **`[2:15–2:45]` Sign-up** — incognito browser, fast cuts: agentaegis.org → "Get Started" → `/pay` (Stripe Checkout, $5 min) → success page → API-key email → app.agentaegis.org Google login → `/account` (balance + 0 calls) → optional `/account/keys` one-time key reveal.
- **`[2:45–3:00]` Outro** — hold on the agentaegis.org homepage with the URL bar visible.

---

## 3. On-screen text & overlays — add in the edit at these cues

- **`[0:05]` title card:** `AgentAegis` · `20 cybersecurity tools for AI agents` · `Pay per call — card or USDC`
- **`[0:40]` lower-third:** `1 endpoint · 2 payment rails · 20 tools · 0 subscriptions`
- **`[1:20]` lower-third:** `$1 · paid via API key · ~9 sec end-to-end`
- **`[2:05]` lower-third:** `$1 · paid via x402 · ~3 sec settlement · txHash on BaseScan`
- **`[2:35]` lower-third:** `2 min · Stripe · $5 minimum · agentaegis.org/pay`
- **`[2:50–3:00]` full-screen hold (4s):** `agentaegis.org` · `github.com/astafford8488` · `[your X handle]`

---

## 4. Recording order & production checklist

**Capture in this order:**
1. **Screen / B-roll first** (Section 2), silent. Get a clean take of each clip — don't narrate live.
2. **Voiceover second** (Section 1), one continuous take. Reading to the finished visuals is far easier than making visuals match a fixed VO.
3. **Edit:** lay the VO on the timeline → drop each visual clip under its matching timecode → add the overlays (Section 3) → burn in captions.

**Before recording:**
- Browser: clear bookmarks bar, hide profile pictures, neutral wallpaper.
- Terminal: clean theme (Solarized or similar), font 16pt+, light background for daytime viewing.
- OBS/Loom: 1080p, 30 fps, audio ≥128 kbps.
- Clear all pre-existing rate-limit / Sentry / cookie banners by hitting the sites in incognito first.
- Stripe in **TEST mode** for the sign-up demo — a real card on screen is a HARD STOP.
- x402 demo wallet funded with ≥$5 USDC on Base mainnet (the demo spends ~$1).
- Demo API key for Demo 1 has ≥$1.00 prepaid balance.
- Kill Slack/Discord/email/all notifications for the session.

**After recording:**
- Edit in CapCut (free) or DaVinci Resolve (free, more powerful).
- Add burned-in captions — 50%+ of YouTube viewers start muted.
- Compress to <100 MB (1080p, h.264, ~3000 kbps).
- Upload to YouTube **Unlisted**; get 3–5 trusted reviewers before going Public.
- Embed on the agentaegis.org hero (above the fold); link from the Show HN body and X thread (tweet 11); add to `/faq` under "Can I see a demo?".

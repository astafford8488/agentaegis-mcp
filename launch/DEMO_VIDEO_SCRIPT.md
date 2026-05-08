# Demo video script — AgentAegis (3 min)

**Format:** Screen recording with voiceover. No talking head needed.
**Recording tool:** OBS Studio (free) or Loom (faster). Loom for the first cut, OBS if you want production-quality after.
**Output:** 1080p MP4, ~80–120 MB. Upload to YouTube (unlisted), embed on agentaegis.org and link from Show HN.
**Total runtime:** 2:55 ± 10s. Anything over 3 min loses 50% of viewers; under 2:30 feels rushed.

---

## Cold open (0:00 – 0:15)

**Visual:** Split screen — left side, Claude Desktop conversation; right side, the AgentAegis MCP server logs streaming in real time.

**Voiceover:**
> "An AI agent just paid ten cents in stablecoin to scan a CVE on a public blockchain. No signup. No subscription. No support ticket. The whole transaction took three seconds."

**On-screen text overlay:**
```
AgentAegis
22 cybersecurity tools for AI agents
Pay per call — card or USDC
```

---

## What it is (0:15 – 0:45)

**Visual:** agentaegis.org marketing page hero, then quick cuts through:
- Pricing table (`/pricing`)
- Tool list (the 22 tools grouped by category)
- The /faq snippet showing pricing examples

**Voiceover:**
> "AgentAegis is an MCP server — Model Context Protocol, the standard agents use to call tools — that lets your AI agent run twenty-two cybersecurity workflows. Vulnerability scans, compliance checks, threat intel, code security, identity audits, the works. The actual scanning is done by the open-source tools you already trust — nmap, Nuclei, Semgrep, sslyze, trufflehog, trivy. What we built is the integration layer that makes them callable from any MCP-compatible agent, plus the unified per-call billing.
>
> Two ways agents pay. A pre-funded API key with a monthly limit, the way most APIs work. Or per call, in USDC, signed cryptographically and settled on chain in three seconds — no account required.
>
> Both rails land on the same endpoint. The agent's MCP client doesn't change. Free tools work without payment so agents can discover what's available before they spend anything."

**On-screen text overlay:**
```
1 endpoint · 2 payment rails · 22 tools · 0 subscriptions
```

---

## Demo 1 — API-key billing (0:45 – 1:30)

**Visual:** Claude Desktop. Pre-configured to point at `https://agentaegis-mcp-production.up.railway.app/mcp` with the demo API key. Real conversation, real call.

**Recording steps (record in this exact order):**
1. Show the Claude Desktop config briefly — the MCP server URL and the `Authorization: Bearer aegis_...` header
2. Send the prompt: "Look up CVE-2024-3094"
3. Claude calls `cve_lookup` tool — show the call appear in MCP logs (right side)
4. Show the response — CVSS score, affected packages, references
5. Cut to the customer portal: balance dropped from $5.00 to $4.90
6. Cut to /account/usage — the call shows up in the table with `paid_via: api_key_balance`

**Voiceover (timed to the visuals above):**
> "Here's a paid call with an API key. Same flow as any modern SaaS API.
>
> The agent calls `cve_lookup` for CVE-2024-3094 — that's the XZ backdoor. Server checks the API key, confirms balance covers the ten-cent price, atomic UPDATE on the customer record so two simultaneous calls can't over-draw, then runs the lookup against NVD.
>
> Nine seconds later, the agent has CVSS, affected packages, references. Customer portal shows the charge — paid via API key, ten cents, balance now four ninety."

**On-screen text overlay** (lower-third, briefly):
```
$0.10 · paid via API key · 9 sec end-to-end
```

---

## Demo 2 — x402 cryptocurrency rail (1:30 – 2:15)

**Visual:** Terminal running an x402-fetch client script. Real Base mainnet wallet. Real settlement.

**Recording steps:**
1. Show the script — it's a single Node script that POSTs to /mcp without any Authorization header
2. Run it. First response: HTTP 402 with payment requirements (show the JSON, highlight `payTo`, `amount`, `extra.name=USDC`)
3. Script signs the ERC-3009 authorization with viem (show the signing log line briefly)
4. Script retries with the X-PAYMENT header
5. Server forwards to facilitator, settles on chain
6. Cut to BaseScan: the actual transaction. $0.10 USDC moved from payer wallet to receiver `0x3347...DF7fC`
7. Back to terminal: the tool result is in stdout
8. Cut to /account/usage in the portal — the call shows up with `paid_via: x402` and `payment_ref` is the transaction hash

**Voiceover:**
> "Now the autonomous version. No API key, no signup, no human in the loop.
>
> The agent posts to /mcp. Server returns four-oh-two — payment required. The agent signs an ERC-3009 transferWithAuthorization for ten cents of USDC. Gasless — the agent doesn't hold ETH.
>
> Server forwards the signed authorization to a facilitator, on-chain settlement completes, agent gets the tool result. Three seconds end-to-end on Base mainnet.
>
> Same usage log, same audit trail. The portal shows it side by side with the API-key call from before — same schema, different payment rail, on-chain transaction hash you can verify on BaseScan right now."

**On-screen text overlay** (lower-third):
```
$0.10 · paid via x402 · 3 sec settlement · txHash on BaseScan
```

---

## Sign-up flow (2:15 – 2:45)

**Visual:** Incognito browser. Fast cuts.

**Recording steps:**
1. Open `agentaegis.org`, click "Get Started"
2. Land on `/pay` (Stripe Checkout). Show the $5 minimum top-up
3. Pay with a test card (Stripe test mode for the recording — note this in post)
4. Get the success page → AgentAegis email arrives with the API key
5. Click `app.agentaegis.org` link → log in with Google
6. Land on /account showing balance + 0 calls
7. Optionally: hit `/account/keys`, click "Issue new key", show the one-time plaintext reveal

**Voiceover:**
> "Sign-up takes about two minutes. Top up at agentaegis.org slash pay — five-dollar minimum, Stripe handles the card. Email arrives with your first API key.
>
> Customer portal at app.agentaegis.org. Google sign-in or magic link. Issue more keys, view usage, configure webhooks, export to CSV. Standard SaaS, except the underlying primitive is per-call billing instead of subscriptions."

**On-screen text overlay:**
```
2 min · Stripe · $5 minimum · agentaegis.org/pay
```

---

## Outro (2:45 – 3:00)

**Visual:** Hold on the agentaegis.org homepage. URL bar visible.

**Voiceover:**
> "agentaegis dot org. Twenty-two tools. Pay per call. No subscriptions. No human in the loop required.
>
> Patent pending on the architecture. Built solo. Try it on your agent today."

**On-screen text overlay (full screen, hold for 4 seconds at the end):**
```
agentaegis.org
github.com/astafford8488

@andrewstafford or whoever — ←  fill in your handle
```

---

## Production checklist

Before recording:

- [ ] Browser windows: clear all bookmarks bars, hide profile pictures, neutral wallpaper
- [ ] Terminal: Solarized or similar clean theme, font 16pt+, white-or-light background for daytime viewing
- [ ] OBS or Loom: record at 1080p, 30 fps, audio bitrate ≥128 kbps
- [ ] Clear ALL pre-existing rate-limit / Sentry / X-Cookie banners on the recorded sites by hitting them in incognito first
- [ ] Stripe is in test mode for the sign-up demo — REAL credit cards on screen are a HARD STOP
- [ ] Wallet for x402 demo has at least $1 of USDC on Base mainnet (the demo uses ~$0.10)
- [ ] Demo API key for Demo 1 has at least $1.00 prepaid balance
- [ ] Disable Slack, Discord, email, every notification source for the recording session

While recording:

- [ ] Don't speak for 2 seconds at the start of each cut — gives editor breathing room
- [ ] Don't apologize for typos or fumbles — re-record the cut, keep the take energy up
- [ ] Cursor moves: deliberate, smooth, never frantic
- [ ] If a real-time transaction takes longer than expected (e.g., 8 sec instead of 3), cut to a B-roll explaining the architecture, then cut back
- [ ] Record the voiceover separately AFTER the screen capture, not live. Way easier to fix mistakes that way

After recording:

- [ ] Edit in CapCut (free) or DaVinci Resolve (free, more powerful)
- [ ] Add captions — at least 50% of YouTube viewers watch muted on first impression
- [ ] Compress to <100 MB for embedding (1080p, h.264, ~3000 kbps)
- [ ] Upload to YouTube as **Unlisted** first. Get 3-5 trusted people to review before going Public
- [ ] Embed on agentaegis.org hero (above the fold)
- [ ] Link from Show HN body and Twitter thread tweet 11
- [ ] Add to /faq under "Can I see a demo?" entry

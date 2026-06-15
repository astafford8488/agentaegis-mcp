# Launch-Day Runbook

Hour-by-hour playbook for the AgentAegis public launch. Goal: a controlled launch where
the operator (Andrew) is never surprised, traffic is watched, and there's a clean abort path.

**Pre-req:** R-3 closed (✅ mainnet x402 verified), API key leak rotated (see Pre-flight),
demo video recorded + uploaded, Bazaar listing live.

---

## Pre-flight checklist (the day BEFORE)

- [ ] **Rotate the leaked API key** (`aegis_z9J5w5…` was public in /faq; revoke + reissue).
- [ ] `curl https://www.agentaegis.org` → 200; hero loads; pricing shows $1/$2/$3/$5.
- [ ] `curl https://agentaegis-mcp-production.up.railway.app/health/deep` → status ok, cdp_mode true.
- [ ] `/mcp` 402 challenge returns v2 (eip155:8453, "USD Coin"). (Already verified.)
- [ ] Status page green: https://status.agentaegis.org
- [ ] Fresh signup works end-to-end in incognito (Stripe test → email → portal login).
- [ ] Demo video live (unlisted), embedded on home, linked in HN body + X tweet 11 + FAQ.
- [ ] Bazaar listing live and discoverable.
- [ ] Top up the demo API key used in the video with real balance (if doing live calls).
- [ ] Block 3–4 hours of clear calendar AFTER the HN submit. No meetings.
- [ ] Have this file, HN_COMMENT_PREP.md, and the status page open in tabs.

---

## T-0: Show HN submission

- **When:** Tuesday or Wednesday, **8:00–9:30am US Eastern**. Avoid Mon (catch-up), Fri (dead),
  and any Apple/YC/OpenAI keynote day (you get buried).
- Submit at https://news.ycombinator.com/submit with the title + URL from `SHOW_HN_DRAFT.md`.
- Immediately post the prepared first comment (the technical "how it works" context) as OP.
- **Do NOT** ask anyone to upvote (HN detects voting rings → auto-bury). Sharing the link is fine.

## T+0 to T+4h: the critical window

This is the whole ballgame. HN posts that get answered fast climb; ones that ghost die.

- **Respond to every comment within ~30–60 min.** Use HN_COMMENT_PREP.md for the hard ones.
- When challenged on a technical claim, link to a **deployed endpoint or the BaseScan tx**,
  not a marketing page. (You have a real mainnet settlement tx — use it.)
- Lead with substance, concede real limitations (atomicity, beta status) — HN rewards candor.
- Watch the rank: top of "new" → front page within ~30 min if it's going to take off.

**Monitor in parallel (keep tabs open):**
- `status.agentaegis.org` — all green.
- `/health/deep` — refresh periodically; if anything flips to degraded, debug visibly.
- Stripe dashboard — watch for signups; confirm webhooks deliver (balance credits land).
- x402: watch the receiver wallet for inbound USDC (real agent payments).
- Railway logs — tail for errors / 500s under load.

## T+2h: stack the channels

- If HN climbed to the front page → post the **X/Twitter thread** (`TWITTER_THREAD.md`),
  quoting the HN permalink in the final tweet. Stacks the signal.
- If HN stalled → still post the thread, but make tweet 11 the primary CTA (skip the dead-HN link).
- Post **r/ClaudeAI** (`launch/reddit/01`) the same morning if HN is stable.

## T+1d onward: the staggered rollout

Per `REDDIT_LAUNCH.md` — do NOT same-day blast (Reddit anti-spam shadowban risk):

| Day | Channel |
|---|---|
| L+1 (Wed) | r/AI_Agents (`reddit/02`) |
| L+2 (Thu) | r/LocalLLaMA (`reddit/03`) |
| L+1 | MCP registry submission (`MCP_REGISTRY_SUBMISSION.md`) |
| L+1 | Cold outreach batch 1 (`OUTREACH_PLAYBOOK.md`) |
| Week 2 Mon | r/cybersecurity (`reddit/04`) |
| Week 2 Tue | r/ethereum (`reddit/05`) — only if mainnet x402 claim holds (it does ✓) |

## Spike handling

- Expect Stripe signups in bursts, not thousands. Portal should handle 50–100 concurrent.
- If `/mcp` latency climbs: it's fine for tool calls to be slow (scans take seconds); the
  concern is the health endpoint or DB. Watch `/health/deep` latency fields.
- If a scanning engine (nmap/nuclei) saturates the scan-slot limit → calls return a clean
  "max concurrent scans" error, not a crash. That's by design; note it if asked.

## Abort / pause criteria (when to pull back, not panic)

- **x402 settlement breaks** (facilitator down) → the "pay per call via USDC" claim is live;
  if it stops working mid-launch, say so in a comment and point users to the API-key rail
  (Stripe), which is independent. Don't hide it — debug in public.
- **Billing bypass discovered** → pause paid tools (they 402), fix, redeploy. The self-audit
  story buys you credibility here: "found one pre-launch, fixed fast" is on-brand.
- **A real vuln reported by an HN/Reddit user** → thank them publicly, fix fast, credit them.
  A security product that handles a bug report gracefully *gains* trust.
- **Sustained 500s / outage** → status page + a pinned comment; fix before pushing more channels.

## After

- Save the HN permalink; pin the X thread for 48h.
- Log every substantive question into the FAQ (`help.ts`) — turns launch Q&A into durable docs.
- Capture metrics for investors: calls/day, unique agents, revenue, repeat rate, HN rank peak.

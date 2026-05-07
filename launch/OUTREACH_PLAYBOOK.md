# Outreach playbook

Companion to the **Cold Outreach** Notion database. The database is the **list**. This is the **process**.

## Cadence

Don't carpet-bomb. Two-week ramp:

| Week | Volume | Targets | Why |
|---|---|---|---|
| Week 1, day 1 | 5 DMs | All 4 P1 directories + 1 P1 framework author | Get directory listings live before Show HN |
| Week 1, day 2 | 8 DMs | All 8 remaining P1s except enterprise | High-fit indie + AI security customers |
| Week 1, day 3-7 | 0 | (waiting) | Let week-1 DMs marinate. People reply within 48-72h or never |
| Week 2, day 1 | 12 DMs | P2 across categories | Wider net once P1 has signal |
| Week 2, day 2-3 | 5 DMs | P2 enterprise + influencer | Final push before Show HN |
| Week 2, end | 0 new | Just follow-ups | Day before Show HN, do nothing — focus on the launch itself |

**Total active outreach over 2 weeks: ~30 DMs.** The remaining 20 P3s are nurture-stage — DM only if there's a specific reason (they tweeted about MCP, they shipped an agent product, etc).

## Verification before sending

The database has `verify` markers on most X handles because I couldn't confirm them with certainty. Before you DM:

1. **Verify the X handle** by Google-searching "[name] [company] twitter" or "[name] x"
2. **Verify the person still works there** — LinkedIn or recent X activity
3. **Skim their last 5 posts** — adjust the DM if they've recently shipped something major or are mid-fundraise
4. **Update the database row** with the correct X Handle and add the Last Contact date when you send

## DM-sending mechanics

### Where to send

Order of preference per target:
1. **X DMs** — fastest response, best for sub-2k-follower founders
2. **LinkedIn** — better for enterprise / big-company contacts, slower response
3. **Email** — last resort, only if you can find a public address (company "info@" doesn't count)

For P1s, send via X first. If no read receipt within 5 days, send the same person a slightly different version on LinkedIn.

### Personalization rule

Every DM should pass the **"would I send this to a friend?"** test. If it reads like a templated mass email, it gets ignored. The database's draft DMs are starting points — adjust each one for:

- A specific recent thing they did (a tweet, a feature ship, a podcast appearance)
- A specific connection between their product and AgentAegis (don't be vague — say *which* tool, *which* user flow)
- The right register (technical for engineers, strategic for founders)

### Length rule

**3 sentences max.** Hook · pitch · ask. If you can't fit it in 3, the angle isn't sharp enough.

## Response handling

### "Tell me more" / "Sure, send a deck"

- Reply within 4 hours. Speed is a signal.
- **Don't send a deck.** Send a 30-second Loom of the demo (Phase 8 Day 1 demo video, with their use case in mind) + 2 specific bullet points relevant to them
- Update database: `Status = Replied`

### "Let's hop on a call"

- Send a Calendly link (or your scheduling tool of choice) immediately
- 15 minutes max for the first call. If they want more, they'll book it
- Update database: `Status = Booked`

### "Not interested" / "Not a fit"

- Reply once, briefly, thanking them. **Do not push back.** Push-back kills future opportunities
- Update database: `Status = Closed-lost`
- Note in `Notes`: the reason if they gave one (it's free customer research)

### Silence (no reply within 7 days)

- Send ONE follow-up DM, lighter than the first. "Hey — bumping this in case it got lost. No pressure if not the right fit."
- Update database: `Status = Sent` and update `Last Contact`
- If they don't reply to the bump within another 7 days, mark `Closed-lost` and move on

### "Quote me in your launch"

(Will sometimes happen with influencers if your pitch lands)

- Get the exact quote text approved by them in writing before using
- Add to the Show HN draft and Twitter thread under "Featured by"
- Update database: `Status = Replied` with note about quote

## Anti-patterns to avoid

- **DMing both the founder and a junior employee at the same company simultaneously** — looks desperate, lands neither. Pick one.
- **Following up more than once** before they've replied at all. After 2 attempts, move on.
- **Pasting the Show HN body into a DM**. The HN post and a DM are different formats; people who'd read both feel duped.
- **DMing during a fundraise** — founders ignore inbound DMs during fundraises. Check Crunchbase / TechCrunch before pinging.
- **DMing on Friday afternoons or weekends.** Tuesday/Wednesday morning is the sweet spot.
- **Mass-tagging in tweets** ("hey @x @y @z come check out my launch"). Annoying, low-conversion, costs you reach.

## Tracking discipline

- **Update Status the same day you send.** A stale database is worse than no database
- **Note any insight in `Notes`** — even one-word notes ("interested in compliance angle", "asked about open-source") compound across 50 contacts
- **Re-prioritize weekly** — if a P3 just shipped a product directly relevant to AgentAegis, move them to P1

## After Show HN

Your Show HN post is itself an outreach action. After it's live:

1. Quote the post to anyone in `Status = Sent` who hasn't replied yet — adds social proof and a fresh hook
2. For anyone in `Status = Replied` but not yet `Booked`, send the HN URL: "FYI we're on HN today, comments are interesting if you have 5 min"
3. Track new inbound from HN as `Inbound` rows added to the database (they aren't on the original 50 list)

## Tools that make this faster

- **Typefully** for X DM drafting (queues with character count)
- **Apollo or Hunter** for finding emails when X DMs fail (skip for the first wave)
- **Buffer or Typefully** for scheduling the post-launch quote tweets

## When to stop

If by week 4 (2 weeks of outreach + 2 weeks of follow-up cycles) you have:
- ≥3 booked demos OR ≥1 customer commit OR ≥1 referenced quote
→ The list is working. Keep going on a maintenance basis (10 new DMs/week)

- 0 demos AND 0 commits AND 0 quotes
→ The list, the angle, or the product needs adjustment before continuing. Pause outreach and post-mortem before sending more cold DMs.

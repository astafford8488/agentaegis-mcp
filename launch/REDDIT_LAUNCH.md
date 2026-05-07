# Reddit Launch Plan

Strategic sequence of Reddit posts targeting 5 subs with sub-tailored content, BEFORE the Show HN attempt. Reddit is lower-stakes social proof generator + bug surfacer; Show HN climbs harder when there's already a Reddit thread to link to.

Mirror surface: Notion under Launch. Each sub gets its own page so you can edit voice/specifics.

## Posting calendar (one sub per day)

Reddit penalizes posting the same content to multiple subs same-day. Space them.

| Day | Sub | Members | Best time (Eastern) | Angle |
|---|---|---|---|---|
| **Tue** | r/ClaudeAI | ~150K | 8–10 am | Claude Desktop integration |
| **Wed** | r/AI_Agents | ~50K | 8–10 am | Agent tooling integration |
| **Thu** | r/LocalLLaMA | ~400K | 9–11 am | Architecture deep-dive |
| **Fri** (skip) | — | — | — | Reddit traffic dies on Fridays |
| **Mon** (next week) | r/cybersecurity | ~700K | 9–11 am | Self-audit findings |
| **Tue** (next week) | r/ethereum | ~1.7M | 11 am – 1 pm | x402 implementation |

After all 5 land, AND ≥3 received some engagement (>10 upvotes or substantive comments), move to Show HN.

## Reddit-specific rules to respect

1. **Read each sub's rules before posting.** Each has its own. Some require "no self-promotion" — adjust framing or skip.
2. **Reddit accounts under 30 days old** get auto-filtered in many subs. Use a seasoned account; if Andrew doesn't have one, use the company account `u/agentaegis` and accept the spam-filter risk OR use a long-standing personal account
3. **Don't include direct sales CTAs in the post body.** Link to agentaegis.org in a comment reply, not the OP. "Where can I try it" comments are organic; jamming a CTA in the post itself triggers downvotes
4. **Engage every comment within 60 minutes** for the first 4 hours. Reddit ranks by engagement velocity
5. **Don't cross-post.** Each post is original to that sub
6. **Don't pitch in DM.** If a commenter asks, reply publicly. DMs feel spammy

## Cross-promotion is poison

If you post to r/ClaudeAI Tuesday and r/AI_Agents Wednesday, **don't link from one to the other.** The two communities partially overlap and "I'm spamming Reddit" perception spreads fast.

The exception: link to the resulting Reddit threads from the eventual Show HN post body — that's expected social proof, not cross-promotion.

## Pre-post checklist (per sub)

- [ ] Sub has been read for 24+ hours; you understand its current top posts and tone
- [ ] Account has at least 50 karma in any sub (needed for some autofilters)
- [ ] Post follows the sub's flair conventions
- [ ] No links in the post body if the sub has anti-link rules (check sidebar)
- [ ] No marketing language ("revolutionary", "game-changing", "AI-powered")
- [ ] Title doesn't say "Show HN" (wrong platform — looks confused)
- [ ] Title is the LITERAL specific thing you built, not a tagline
- [ ] Body leads with value/lesson/data, not the product

## Engagement playbook

### When the post climbs (>50 upvotes in first hour)

- Reply to every top-level comment with substance, not "great point!"
- If asked "how does it compare to X" — answer directly with bullets, not deflection
- Don't link out unprompted; if asked, link

### When someone calls out a bug or weakness

- Lead with: "You're right, [specific thing]." Don't argue
- If you have a fix or fix-in-progress, mention it and the timeline
- Treat the comment as a free QA session

### When someone is hostile

- Reply ONCE with substance. Don't go further.
- Don't downvote. Don't reply to subsequent inflammatory comments
- Other readers are watching; you only need to look reasonable to bystanders, not convince the hostile commenter

### When the post stalls (<10 upvotes after 2 hours)

- Don't beg friends to upvote. Reddit detects this
- Don't repost. Repost-detection algorithms penalize the second account
- Take it as data — the angle didn't work for that sub. Adjust before next sub
- Move on; tomorrow's a different sub

## What to do AFTER all 5 sub posts

Aggregate the comment threads into a single Notion page (`Reddit Launch Outcomes`) with:
- Total upvotes / downvotes per post
- 3 best questions/critiques received
- Bug reports received → file as github issues
- Quotable comments → save for Show HN body or Twitter thread
- Conversion signal: anyone who sign-up'd from Reddit traffic (track via Stripe metadata or `?ref=reddit-claudeai` query param if you set that up)

Then move to Show HN with the Reddit threads as evidence of real demand.

## Pre-launch prerequisite (CRITICAL)

**Do not post any Reddit content until the red-team plan is fully executed and findings are mitigated.** Reddit posts surface AgentAegis to thousands of technical readers, some of whom WILL try to break it. Going in with unhardened crypto-payment infrastructure is a recipe for "Reddit found my bug live" — embarrassing and brand-damaging.

Specifically:
- All P1 attacks in `audit/RED_TEAM_PLAN.md` must be `PASS` or `Mitigated`
- All P2 attacks must be `PASS`, `Mitigated`, or have a documented accepted-risk note in `audit/RED_TEAM_REPORT.md`
- The Railway auto-deploy gap (Better Stack monitor #2) must be fixed so `/health/deep` works under load

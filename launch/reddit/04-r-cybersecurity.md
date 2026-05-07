# r/cybersecurity post

**Sub:** https://www.reddit.com/r/cybersecurity/
**Day:** Monday week 2 (gap intentional — cybersec sub has different traffic patterns from r/AI_Agents and r/LocalLLaMA)
**Best time:** 9–11 am Eastern
**Flair:** "Discussion" — NOT "News" or "Career"

⚠️ **Critical:** r/cybersecurity is allergic to TWO things at once: AI marketing AND crypto. Both are present in AgentAegis. Lead with the SELF-AUDIT FINDINGS as the value, treat the AI/crypto as implementation detail at the end. Crypto mention should be SHORT and matter-of-fact.

## Title

```
I built a security scanner. Then I scanned myself with it. Found 12 issues, fixed 7. Here's the audit.
```

**Why this title:**
- Story format ("I did X, learned Y")
- Specific numbers (12, 7) signal substance
- No mention of AI, agent, MCP, or crypto in the title
- "Here's the audit" promises value (something readers can read or steal patterns from)

## Body

```
Built a hosted security scanning service. Standard stuff — CVE lookup, port
scan, SSL audit, secret scan, dependency audit, threat intel against
abuse.ch / AbuseIPDB / OTX, DNS / DMARC / SPF check, compliance posture
checks, etc.

Then I ran the whole thing on its own production infrastructure for a
phase-4 self-audit before launch. Twelve findings. Seven fixed in code,
five accepted as documented risks.

The five that mattered most:

1. Billing bug in my own tool dispatch wrapper. The wrapper had:

       if (price === 0) return handler(args);          // free tools
       if (ctx?.x402Settled) return handler(args);     // x402 rail paid
       // ...nothing for the API-key path

   So API-key-paid tools dispatched WITHOUT charging. Caught by the
   pricing-discrepancy check that the audit ran. Fixed by adding the
   API-key debit between the check and the handler call.

2. DMARC policy missing on the marketing domain. Anyone could spoof
   noreply@<our-domain> and send phishing as us. Fix was a single
   TXT record (DMARC v=DMARC1; p=quarantine; pct=100; rua=mailto:...).
   Tool flipped its grade from F to A on re-scan.

3. CAA records missing on both the marketing domain and the corporate
   email domain. Without CAA, ANY CA can issue certs for our domains.
   Fix is 4 DNS records constraining to letsencrypt.org. Took 2 minutes
   in Cloudflare.

4. ROBOT-vulnerability false positive in our own SSL/TLS auditor that
   was actually a real bug:

       if (cert.robotVulnerable !== "NOT_VULNERABLE_NO_ORACLE")

   When the field was undefined (e.g., RSA key exchange not used by
   the server), this evaluates to true and marked clean servers as
   vulnerable. Fix: explicit null check first.

5. Webhook delivery had no SSRF prevention on customer-supplied URLs.
   A customer could register a webhook URL like
   http://169.254.169.254/latest/meta-data/ (AWS metadata endpoint) and
   when our server tried to deliver, it would fetch the metadata and
   send the response body back. Fix: URL validation rejecting RFC 1918,
   loopback, link-local, and metadata IPs at registration AND delivery
   time (defense-in-depth against DNS rebinding).

The five accepted risks are documented in the audit report — mostly
"upstream provider has the issue, we trust their fix" things (X.509
chain depth, Supabase logs retention, Stripe endpoint TLS version).

Two takeaways I keep coming back to:

A. Tools that run security audits are uniquely positioned to be the FIRST
   customer of those tools. If your scanner can't survive being scanned
   by itself, that's a bug in the scanner, not just the target.

B. The most embarrassing finding is almost always something that should
   have been caught by code review or unit tests, not by a scanner.
   The billing bug in finding #1 had no test. We should have had a test.

The actual scanner (AgentAegis) is hosted at agentaegis.org. Mostly
posted here because the audit pattern works regardless of what tool you're
using — it's worth burning a few hours running your own product against
its own production environment before any launch.

Happy to share the report itself if anyone wants the actual findings
write-up.
```

## Pinned reply

```
Audit report (slightly redacted to remove specific IP ranges) at
audit/REPORT.md in our repo. Reproduction steps for each finding are in
the same file. The scanner toolset itself is at agentaegis.org if anyone
wants to point it at their own infrastructure for a quick spot-check.

If your tools can't audit themselves end-to-end, that's the first audit
to run.
```

## Anti-patterns specific to this sub

- DO NOT mention "AI" or "agent" or "LLM" in the title or first paragraph. The sub will not engage.
- DO NOT mention "USDC" / "crypto" / "x402" / "blockchain" in the post body. Mentioning crypto makes 30% of the audience downvote on principle. The product mention near the end is the one place to acknowledge it exists; even there, "an alternative no-signup pay path that uses a stablecoin" is enough.
- DO show real code, real findings, real numbers. r/cybersecurity respects evidence
- Honesty about misses (the billing bug should have had a unit test) earns more credibility than self-promotion

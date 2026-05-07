# r/ethereum post

**Sub:** https://www.reddit.com/r/ethereum/
**Day:** Tuesday week 2
**Best time:** 11 am – 1 pm Eastern (overlaps US + EU traffic)
**Flair:** "Application" or "Discussion" (check current convention)

⚠️ **Critical:** r/ethereum is allergic to AI marketing. Lead with the x402 / ERC-3009 implementation lessons. AI is the use case at the end, not the angle.

## Title

```
Shipped HTTP 402 + ERC-3009 micropayments end-to-end on Base mainnet — three protocol gotchas not in either spec
```

**Why this title:**
- Names HTTP 402 + ERC-3009 (specific Ethereum-standard reference)
- "End-to-end on Base mainnet" is concrete (not testnet, not coming soon)
- "Three gotchas" promises actionable takeaways
- No mention of AI, agent, MCP

## Body

```
Built an HTTP service where the server returns HTTP 402 with payment
requirements, the client signs an ERC-3009 transferWithAuthorization
(gasless from the payer's perspective), the server forwards to a facilitator
for verification, on-chain settlement happens on Base mainnet, then the
service returns the requested resource. End-to-end median latency around
3 seconds.

The protocol layer (HTTP 402 + ERC-3009 + EIP-712) is well documented but
the integration isn't. Three things that broke that aren't in either spec:

1. The X-PAYMENT header is base64-encoded JSON. Reasonable enough — it
   keeps the header value HTTP-safe. But the facilitator's /verify and
   /settle endpoints want the DECODED object as the paymentPayload field,
   not the base64 string. Sending the encoded string returns a generic
   "invalid_*" error that doesn't immediately suggest the encoding issue.

2. Payment requirements have to include the EIP-712 typed-data domain
   in the "extra" field. For USDC on Base / Ethereum, that's
   {name: "USDC", version: "2"}. Without it, the facilitator returns
   invalid_exact_evm_missing_eip712_domain — because it can't reconstruct
   the domain separator to verify the signature. Different stablecoins
   have different domains: USDT on Ethereum is {name: "Tether USD",
   version: "1"}; DAI is {name: "Dai Stablecoin", version: "1"}. You
   can't hardcode one and forget about it.

3. The "resource" field has to be a fully-qualified URL (scheme + host
   + path), not just a path. The reference x402-fetch client zod-validates
   this and rejects path-only values before signing. The server has to
   construct the full URL from the request — protocol + host + originalUrl.

These three together are the difference between "x402 works in 30 minutes
of integration" and "I spent 2 days debugging unhelpful error codes."

A few things worth noting that I figured out in the process:

- Replay protection is via the ERC-3009 nonce. The on-chain contract
  records consumed nonces; second settlement with the same nonce reverts.
  So you can't replay a captured X-PAYMENT to spend the same authorization
  twice. Tested this end-to-end on mainnet (the second attempt did fail
  as expected).

- The dual-rail pattern (per-call USDC OR pre-funded API-key debit) on
  the same endpoint is a useful design. The client signals which rail
  by HTTP header (X-PAYMENT vs Authorization). Server routes accordingly.

- Median end-to-end latency on Base is ~3 sec — fast enough to embed in
  a single HTTP request lifecycle. Compared to a Stripe Checkout redirect
  flow, that's a step-function improvement for non-human-mediated callers.

The use case I built this for is per-call billing of API tools that
non-human clients (no card, no email) can call. Code is at agentaegis.org
if anyone wants to see how the integration actually looks.

Has anyone else shipped x402 to mainnet? Curious about facilitator
choices, alternative networks (Arbitrum / Polygon / Optimism support
varies), and whether anyone's running a self-hosted facilitator.
```

## Pinned reply

```
For anyone wanting to build along, here's the minimal viable client side
using x402-fetch and viem:

    import { withPaymentInterceptor } from "x402-fetch";
    import { privateKeyToAccount } from "viem/accounts";

    const account = privateKeyToAccount(process.env.PAYER_KEY);
    const paidFetch = withPaymentInterceptor(fetch, account);

    const res = await paidFetch("https://server/api/protected-resource", {
      method: "POST",
      body: JSON.stringify({ ... }),
    });

The interceptor handles the 402 challenge, signing, and retry. From the
caller's perspective, it's just fetch().

USDC contract addresses for reference:
  Base mainnet:  0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913
  Ethereum:      0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
  Polygon:       0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359

EIP-712 domains differ per chain — don't hardcode.
```

## Anti-patterns specific to this sub

- Don't lead with "AI agents pay USDC." That triggers the "this is a vibes-not-tech post" pattern-match
- Don't mention ICOs, tokens, "Web3 [thing]", or anything that smells like crypto-marketing
- DO mention specific contract addresses, EIP numbers, gas considerations, latency benchmarks
- DO acknowledge alternative L2s and chains — implying Ethereum mainnet is the only option will get pushback
- DO link to ERC-3009 spec / EIP-712 docs in replies for any reader who isn't familiar

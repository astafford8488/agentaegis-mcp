# Manual procedure: A1 — x402 Replay attack

**Severity if successful:** P1 (bypass billing entirely on x402 rail)
**Time to execute:** ~10 minutes
**Cost:** ~$0.10 USDC on Base mainnet
**Pre-req:** Funded test wallet at `0x1baC8AC7Fdd826b0C47C0eba0858d2BFCf8D0086` (the existing AgentAegis test funding wallet, ~$5 USDC remaining)

## Hypothesis

If we capture an X-PAYMENT header from a successful tool call, can we POST it again to spend the same on-chain authorization twice?

## Expected defense

The ERC-3009 `transferWithAuthorization` includes a 32-byte nonce. The on-chain contract records consumed nonces; second settlement attempt reverts. The x402 facilitator should also reject pre-settled authorizations during /verify.

## Steps

1. **Capture a real X-PAYMENT** by running the existing test:

   ```bash
   cd C:/Users/thega/Downloads/AgentAegis/agentaegis-mcp
   pnpm tsx audit/x402-test/02-run-payment.ts
   ```

   Note the X-PAYMENT header sent (log it from inside the test runner if it doesn't already log).

2. **Replay attempt — script**

   Create a one-off script that POSTs the same X-PAYMENT a second time:

   ```bash
   cat > /tmp/replay-test.ts <<'EOF'
   const TARGET = "https://agentaegis-mcp-production.up.railway.app/mcp";
   const CAPTURED_X_PAYMENT = "<paste the captured base64 header here>";

   const body = JSON.stringify({
     jsonrpc: "2.0",
     id: 1,
     method: "tools/call",
     params: { name: "cve_lookup", arguments: { cve_id: "CVE-2024-3094" } },
   });

   const res = await fetch(TARGET, {
     method: "POST",
     headers: { "Content-Type": "application/json", "X-PAYMENT": CAPTURED_X_PAYMENT },
     body,
   });
   console.log("Status:", res.status);
   console.log("Body:", await res.text());
   EOF
   pnpm tsx /tmp/replay-test.ts
   ```

3. **Expected result**

   - HTTP 402
   - Body contains an error mentioning settlement failure or invalid authorization
   - The `transferWithAuthorization` on-chain attempt reverts (verify on BaseScan if possible)

4. **What constitutes a finding**

   - **PASS**: Second attempt returns 402 and no second settlement happens
   - **FAIL (P1)**: Second attempt returns 200 AND tool result is delivered AND no second on-chain transaction → billing bypass
   - **FAIL (P2)**: Second attempt returns 200 with cached result but no second settlement → not a billing bypass but unexpected behavior
   - **INDETERMINATE**: Verify result needs scrolling — log everything

## Recording the finding

Append to `audit/RED_TEAM_REPORT.md`:

```markdown
### Finding R-A1 — x402 replay attack
- **Severity:** [PASS / P1 / P2]
- **Reproducer:** /tmp/replay-test.ts (capture exact CAPTURED_X_PAYMENT used)
- **Result:** [exact response]
- **Mitigation:** [if FAIL, what we change]
- **Tested by:** Andrew Stafford
- **Date:** [YYYY-MM-DD]
```

## Cleanup

Delete `/tmp/replay-test.ts` (contains real captured payment header). The header itself can't be reused after the test completes (nonce is consumed) but treat as sensitive ephemeral data.

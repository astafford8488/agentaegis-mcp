# Manual procedure: A2 — Signature substitution

**Severity if successful:** P1 (pay $0.10, get $1.00 worth of tools)
**Time:** ~15 minutes
**Cost:** ~$0.10 USDC on Base mainnet
**Pre-req:** Same test funding wallet as A1

## Hypothesis

If the EIP-712 typed data domain doesn't bind the `resource` URL into the signed payload, an attacker can sign an authorization for a $0.10 tool, then change the X-PAYMENT to apply to a $1.00 tool's resource URL.

## Expected defense

EIP-712 domain {name:"USDC", version:"2"} binds the typed data structure into the signature. Tampering with `resource` after signing should cause the facilitator to compute a different domain hash; signature verification fails.

## Steps

1. Pick two tools with different prices. From `src/types/mcp.ts`:
   - cheap: `cve_lookup` ($0.10)
   - expensive: `compliance_check` ($1.00)

2. **Sign for the cheap tool**

   Modify `audit/x402-test/02-run-payment.ts` to call `cve_lookup`. Run it. Capture the signed X-PAYMENT.

3. **Replace resource URL**

   The X-PAYMENT is base64-encoded JSON. Decode:

   ```bash
   echo '<captured base64>' | base64 -d | jq .
   ```

   Find the `resource` field. It will be `https://agentaegis-mcp-production.up.railway.app/mcp` — but the facilitator's payment requirements include the exact tool's price in `maxAmountRequired`. Now try:

   - Modify the body's `params.name` from `cve_lookup` to `compliance_check`
   - Keep the X-PAYMENT unchanged (or modify the resource URL inside the X-PAYMENT — try both)

4. **Submit**

   POST to /mcp with:
   - `params.name: "compliance_check"` (10× the price)
   - X-PAYMENT: the cve_lookup-priced authorization

5. **Expected result**

   - Server constructs payment requirements for compliance_check ($1.00)
   - Sends original X-PAYMENT to facilitator
   - Facilitator's /verify either:
     - **PASS**: rejects with `invalid_exact_evm_*` error because the signed amount ($0.10) doesn't match the required amount ($1.00)
     - **FAIL (P1)**: accepts, settles $0.10, server runs compliance_check (a $1.00 tool) → 90% discount via signature substitution

## Recording

Same template as A1. Tag as A2 in the report.

## Variant — resource URL injection

Try the same but modify the URL path: change `resource` from `/mcp` to `/mcp?priority=high` or similar. Validates that the facilitator does exact-match URL comparison.

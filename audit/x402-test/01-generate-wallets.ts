// Generates two Base Sepolia test wallets:
//   - receiver: AgentAegis server's payee address (where USDC lands)
//   - payer:    fake agent's wallet that will sign payments
//
// Saves keypairs to wallets.json (gitignored). Both keys are TESTNET ONLY —
// never expose mainnet private keys this way.

import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import * as fs from "fs";
import * as path from "path";

const __dirname = import.meta.dirname || ".";

function makeWallet(label: string) {
  const privateKey = generatePrivateKey();
  const account = privateKeyToAccount(privateKey);
  return {
    label,
    address: account.address,
    private_key: privateKey,
    chain: "base-sepolia",
  };
}

const wallets = {
  receiver: makeWallet("AgentAegis x402 receiver (testnet)"),
  payer: makeWallet("Test agent payer (testnet)"),
  generated_at: new Date().toISOString(),
  warning: "TESTNET ONLY — never use these private keys on mainnet. Anyone reading this file has full control of these wallets.",
};

const outFile = path.join(__dirname, "wallets.json");
fs.writeFileSync(outFile, JSON.stringify(wallets, null, 2));

console.log("Generated test wallets:");
console.log("  Receiver (X402_PAYEE_ADDRESS):", wallets.receiver.address);
console.log("  Payer    (test agent):        ", wallets.payer.address);
console.log("");
console.log("Saved to:", outFile);
console.log("");
console.log("Next steps:");
console.log("  1. Set X402_PAYEE_ADDRESS=" + wallets.receiver.address + " on Railway");
console.log("  2. Fund the payer with Base Sepolia ETH + USDC from a faucet:");
console.log("     • https://faucet.circle.com (USDC) — paste:", wallets.payer.address);
console.log("     • https://www.alchemy.com/faucets/base-sepolia (ETH)");
console.log("  3. Run 02-run-payment.ts to do the full 402 flow");

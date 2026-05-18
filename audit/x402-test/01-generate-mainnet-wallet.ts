// Generates a single throwaway PAYER wallet for the Base MAINNET x402 test.
//
// Unlike 01-generate-wallets.ts (which creates a testnet receiver+payer pair),
// this script only generates a payer. The receiver is the AgentAegis production
// Smart Wallet (X402_PAYEE_ADDRESS=0x3347d4E9925cC379a333c017367248e1A11DF7fC),
// which is passkey-based and has no exportable private key.
//
// ⚠️ MAINNET — real funds. Treat the private key as a one-time-use secret. After
// the test passes, sweep any remaining USDC + ETH back to your Smart Wallet and
// delete wallets-mainnet.json.
//
// Output: audit/x402-test/wallets-mainnet.json  (gitignored — whole dir is)

import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import * as fs from "fs";
import * as path from "path";

const __dirname = import.meta.dirname || ".";

const privateKey = generatePrivateKey();
const account = privateKeyToAccount(privateKey);

const RECEIVER = "0x3347d4E9925cC379a333c017367248e1A11DF7fC"; // AgentAegis production payee

const wallets = {
  network: "base",
  network_chain_id: 8453,
  receiver: {
    label: "AgentAegis production x402 receiver (Coinbase Smart Wallet, passkey)",
    address: RECEIVER,
    private_key: null, // not exportable — passkey-based
  },
  payer: {
    label: "Throwaway test payer (mainnet EOA, single-use)",
    address: account.address,
    private_key: privateKey,
    chain: "base",
  },
  generated_at: new Date().toISOString(),
  warning:
    "MAINNET. The payer private key controls real funds. Sweep remaining USDC + ETH back to your Smart Wallet after the test and delete this file.",
};

const outFile = path.join(__dirname, "wallets-mainnet.json");
fs.writeFileSync(outFile, JSON.stringify(wallets, null, 2));

console.log("=".repeat(72));
console.log("Mainnet payer EOA generated");
console.log("=".repeat(72));
console.log("Payer address:", account.address);
console.log("Receiver:     ", RECEIVER);
console.log("Network:       Base mainnet (chain ID 8453)");
console.log("");
console.log("Saved to:     ", outFile);
console.log("");
console.log("─".repeat(72));
console.log("Next: fund the payer from your Coinbase Smart Wallet on Base mainnet:");
console.log("");
console.log("  • USDC: send $1.00 USDC to     " + account.address);
console.log("      (USDC contract: 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913)");
console.log("  • ETH:  send ~$0.10 ETH to    " + account.address);
console.log("      (needed for gas; ~0.00003 ETH on Base, but send a bit extra)");
console.log("");
console.log("Then verify the funding on BaseScan:");
console.log("  https://basescan.org/address/" + account.address);
console.log("");
console.log("When confirmed (~30 sec), run:");
console.log("  pnpm tsx audit/x402-test/02-run-mainnet-payment.ts");
console.log("=".repeat(72));

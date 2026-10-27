/**
 * Create an Algorand TestNet wallet (account).
 * Prints address + mnemonic. Fund via https://bank.testnet.algorand.network/
 * then opt into USDC ASA 10458941.
 *
 * For merchant≠payer e2e: run twice — once for payer (ALGORAND_MNEMONIC),
 * once for merchant (MERCHANT_ADDRESS only; keep that mnemonic offline /
 * do not use it as payer).
 *
 * Usage: pnpm exec tsx scripts/create-wallet.ts
 */
import algosdk from "algosdk";

const account = algosdk.generateAccount();
const mnemonic = algosdk.secretKeyToMnemonic(account.sk);

console.log("Algorand TestNet wallet created");
console.log("Address:", account.addr.toString());
console.log("Mnemonic:", mnemonic);
console.log("");
console.log("Next (merchant ≠ payer):");
console.log("  1. Fund ALGO: https://bank.testnet.algorand.network/");
console.log("  2. Opt-in USDC ASA 10458941 (Dispenser / wallet)");
console.log("  3. Payer:  export ALGORAND_MNEMONIC='<payer mnemonic>'");
console.log("  4. Merchant (receive-only): export MERCHANT_ADDRESS=<merchant address>");
console.log("     (merchant must also be opted into USDC; do not reuse payer mnemonic as merchant signer)");
console.log("  5. pnpm demo   # then pnpm e2e:paid");

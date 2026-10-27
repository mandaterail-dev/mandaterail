import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";

function loadDotEnv() {
  for (const p of [resolve(process.cwd(), ".env"), resolve(import.meta.dirname, "../.env")]) {
    if (!existsSync(p)) continue;
    for (const line of readFileSync(p, "utf8").split(/\r?\n/)) {
      const t = line.trim();
      if (!t || t.startsWith("#")) continue;
      const i = t.indexOf("=");
      if (i <= 0) continue;
      const key = t.slice(0, i).trim();
      let val = t.slice(i + 1).trim();
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'")))
        val = val.slice(1, -1);
      if (process.env[key] === undefined) process.env[key] = val;
    }
    break;
  }
}
loadDotEnv();

/**
 * A→Z TestNet paid path:
 *   1. Load ALGORAND_MNEMONIC
 *   2. Sign IntentMandate (ed25519)
 *   3. Opt into USDC if needed
 *   4. GET /paid/resource → 402 PaymentRequirements
 *   5. Build fee-payer + axfer paymentGroup
 *   6. POST verify+settle via demo-api with X-PAYMENT + X-MANDATE
 *   7. Expect HTTP 200
 *
 * Usage (merchant ≠ payer):
 *   export ALGORAND_MNEMONIC="..."          # payer signs + funds USDC
 *   export MERCHANT_ADDRESS="..."           # receive-only payTo (opted into USDC)
 *   # start demo-api in another terminal
 *   pnpm exec tsx scripts/e2e-paid.ts
 */

import algosdk from "algosdk";
import { signMandate } from "@mandaterail/core";
import type { IntentMandate } from "@mandaterail/schema";
import {
  ALGORAND_TESTNET_CAIP2,
  USDC_TESTNET_ASA,
  GOPLAUSIBLE_FEE_PAYER,
  toAtomicAmount,
} from "@mandaterail/middleware-hono";

const DEMO_URL = process.env.DEMO_API_URL ?? "http://127.0.0.1:8787";
const ALGOD =
  process.env.ALGOD_URL ?? "https://testnet-api.algonode.cloud";
const MNEMONIC = process.env.ALGORAND_MNEMONIC;
const MERCHANT = process.env.MERCHANT_ADDRESS;
const PRICE = process.env.PRICE_USDC ?? "0.01";
const ASA = Number(process.env.USDC_ASA_ID ?? USDC_TESTNET_ASA);
const NETWORK = process.env.NETWORK ?? ALGORAND_TESTNET_CAIP2;
const FEE_PAYER = process.env.FEE_PAYER ?? GOPLAUSIBLE_FEE_PAYER;

if (!MNEMONIC) {
  console.error("ALGORAND_MNEMONIC is required");
  process.exit(1);
}
if (!MERCHANT) {
  console.error("MERCHANT_ADDRESS is required");
  process.exit(1);
}

function b64(u8: Uint8Array): string {
  return Buffer.from(u8).toString("base64");
}

async function ensureUsdcOptIn(
  algod: algosdk.Algodv2,
  account: algosdk.Account,
): Promise<void> {
  const info = await algod.accountInformation(account.addr).do();
  const assets = (info.assets ?? []) as Array<{ assetId?: bigint | number; "asset-id"?: number }>;
  const opted = assets.some((a) => {
    const id = Number(a.assetId ?? a["asset-id"] ?? 0);
    return id === ASA;
  });
  if (opted) {
    console.log("USDC opt-in: already opted in");
    return;
  }
  console.log("USDC opt-in: submitting...");
  const sp = await algod.getTransactionParams().do();
  const opt = algosdk.makeAssetTransferTxnWithSuggestedParamsFromObject({
    sender: account.addr,
    receiver: account.addr,
    amount: 0,
    assetIndex: ASA,
    suggestedParams: sp,
    note: new TextEncoder().encode("mandaterail-usdc-optin"),
  });
  const signed = opt.signTxn(account.sk);
  const { txid } = await algod.sendRawTransaction(signed).do();
  await algosdk.waitForConfirmation(algod, txid, 4);
  console.log("USDC opt-in confirmed:", txid);
}

async function main() {
  const account = algosdk.mnemonicToSecretKey(MNEMONIC!);
  const addr = account.addr.toString();
  console.log("Payer (ALGORAND_MNEMONIC):", addr);
  console.log("Merchant (MERCHANT_ADDRESS payTo):", MERCHANT);
  if (addr === MERCHANT) {
    console.warn(
      "WARN: payer === merchant. For merchant≠payer e2e use a distinct MERCHANT_ADDRESS (receive-only).",
    );
  } else {
    console.log("merchant≠payer: OK");
  }
  console.log("Price:", PRICE, "USDC");

  const algod = new algosdk.Algodv2("", ALGOD, "");

  // 1) Sign mandate
  const now = new Date();
  const later = new Date(now.getTime() + 60 * 60 * 1000);
  const unsigned: Omit<IntentMandate, "signature"> = {
    id: `e2e-${now.getTime()}`,
    principal: addr,
    agent: "did:example:e2e-agent",
    maxAmount: "1.00",
    asset: "USDC",
    allowlist: ["demo-merchant"],
    expiresAt: later.toISOString(),
    revoked: false,
    nonce: `nonce-${now.getTime()}`,
    createdAt: now.toISOString(),
    metadata: { purpose: "e2e-paid" },
  };
  const signature = signMandate(unsigned, account.sk);
  const mandate: IntentMandate = { ...unsigned, signature };

  // Register mandate with demo-api
  const reg = await fetch(`${DEMO_URL}/demo/mandates`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(mandate),
  });
  if (!reg.ok) {
    console.error("Failed to register mandate", reg.status, await reg.text());
    process.exit(1);
  }
  console.log("Mandate registered:", mandate.id);

  await ensureUsdcOptIn(algod, account);

  // 2) Probe 402
  const probe = await fetch(`${DEMO_URL}/paid/resource`);
  if (probe.status !== 402) {
    console.error("Expected 402, got", probe.status, await probe.text());
    process.exit(1);
  }
  const body = (await probe.json()) as {
    accepts?: Array<Record<string, unknown>>;
    payment?: Record<string, unknown>;
  };
  const requirements = (body.accepts?.[0] ?? body.payment) as {
    scheme: string;
    network: string;
    asset: string;
    amount: string;
    payTo: string;
    maxTimeoutSeconds?: number;
    extra?: { feePayer?: string; decimals?: number };
  };
  console.log("402 requirements amount (atomic):", requirements.amount);
  console.log("402 payTo:", requirements.payTo);

  // 3) Build payment group: [unsigned fee pay, signed axfer]
  const sp = await algod.getTransactionParams().do();
  const feePayer = String(requirements.extra?.feePayer ?? FEE_PAYER);
  const amountAtomic = BigInt(requirements.amount);
  const payTo = String(requirements.payTo);

  const feeTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: feePayer,
    receiver: feePayer,
    amount: 0,
    suggestedParams: {
      ...sp,
      fee: 2000,
      flatFee: true,
    },
    note: new TextEncoder().encode("x402-fee-payer"),
  });

  const axfer = algosdk.makeAssetTransferTxnWithSuggestedParamsFromObject({
    sender: account.addr,
    receiver: payTo,
    amount: amountAtomic,
    assetIndex: Number(requirements.asset ?? ASA),
    suggestedParams: {
      ...sp,
      fee: 0,
      flatFee: true,
    },
    note: new TextEncoder().encode("x402-payment-v2"),
  });

  const grouped = algosdk.assignGroupID([feeTxn, axfer]);
  const feeBytes = algosdk.encodeUnsignedTransaction(grouped[0]);
  const axferSigned = grouped[1].signTxn(account.sk);

  const paymentPayload = {
    x402Version: 2,
    scheme: "exact",
    network: requirements.network ?? NETWORK,
    payload: {
      paymentGroup: [b64(feeBytes), b64(axferSigned)],
      paymentIndex: 1,
    },
  };

  const xPayment = Buffer.from(JSON.stringify(paymentPayload)).toString(
    "base64",
  );

  // 4) Paid request
  const paid = await fetch(`${DEMO_URL}/paid/resource`, {
    headers: {
      "X-PAYMENT": xPayment,
      "X-MANDATE-ID": mandate.id,
      "X-MANDATE": JSON.stringify(mandate),
    },
  });
  const text = await paid.text();
  console.log("Paid status:", paid.status);
  console.log("Paid body:", text);
  if (paid.status !== 200) {
    process.exit(1);
  }
  try {
    const json = JSON.parse(text) as {
      receiptId?: string | null;
      explorerUrl?: string | null;
    };
    console.log("receiptId:", json.receiptId);
    console.log("explorerUrl:", json.explorerUrl);
  } catch {
    /* ignore */
  }
  console.log("E2E paid path OK");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

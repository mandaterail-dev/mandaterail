import type { IntentMandate, PendingApproval, Receipt } from "../lib/types";
import {
  ALGORAND_TESTNET_CAIP2,
  DEMO_MERCHANT_ADDRESS,
  DEMO_PRINCIPAL,
  USDC_ASA_ID,
} from "../lib/fixtures";

const now = Date.now();
const day = 24 * 60 * 60 * 1000;

export const mockMandates: IntentMandate[] = [
  {
    id: "mandate-demo-1",
    principal: DEMO_PRINCIPAL,
    agent: "did:example:agent-1",
    maxAmount: "25.00",
    asset: "USDC",
    allowlist: ["demo-merchant"],
    expiresAt: new Date(now + day).toISOString(),
    revoked: false,
    nonce: "nonce-demo-1",
    signature: "sig_demo_stub",
    createdAt: new Date(now - 2 * 60 * 60 * 1000).toISOString(),
    metadata: { note: "Active TestNet mandate", asa: USDC_ASA_ID },
  },
  {
    id: "mandate-demo-2",
    principal: DEMO_PRINCIPAL,
    agent: "did:example:agent-2",
    maxAmount: "5.00",
    asset: "USDC",
    allowlist: ["demo-merchant"],
    expiresAt: new Date(now + 6 * 60 * 60 * 1000).toISOString(),
    revoked: false,
    nonce: "nonce-demo-2",
    signature: null,
    createdAt: new Date(now - 30 * 60 * 1000).toISOString(),
    metadata: { note: "Unsigned draft" },
  },
  {
    id: "mandate-demo-revoked",
    principal: DEMO_PRINCIPAL,
    agent: "did:example:agent-1",
    maxAmount: "100.00",
    asset: "USDC",
    allowlist: ["demo-merchant"],
    expiresAt: new Date(now + day).toISOString(),
    revoked: true,
    nonce: "nonce-demo-revoked",
    signature: "sig_demo_revoked",
    createdAt: new Date(now - day).toISOString(),
  },
];

export const mockReceipts: Receipt[] = [
  {
    receiptId: "receipt-demo-1",
    mandateId: "mandate-demo-1",
    txId: "MOCKTXIDABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCD",
    network: ALGORAND_TESTNET_CAIP2,
    payer: DEMO_PRINCIPAL,
    merchant: DEMO_MERCHANT_ADDRESS,
    amount: "0.01",
    asset: String(USDC_ASA_ID),
    createdAt: new Date(now - 45 * 60 * 1000).toISOString(),
    explorerUrl:
      "https://explore.algokit.io/testnet/transaction/MOCKTXIDABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCD",
  },
  {
    receiptId: "receipt-demo-2",
    mandateId: "mandate-demo-1",
    txId: "MOCKTXID2BCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCE",
    network: ALGORAND_TESTNET_CAIP2,
    payer: DEMO_PRINCIPAL,
    merchant: DEMO_MERCHANT_ADDRESS,
    amount: "0.01",
    asset: String(USDC_ASA_ID),
    createdAt: new Date(now - 10 * 60 * 1000).toISOString(),
    explorerUrl:
      "https://explore.algokit.io/testnet/transaction/MOCKTXID2BCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCE",
  },
];

export let mockPending: PendingApproval[] = [
  {
    id: "pending-demo-1",
    status: "pending",
    createdAt: new Date(now - 5 * 60 * 1000).toISOString(),
    mandateId: "mandate-demo-1",
    sig_hint: "approve-spend",
    display_hint: "Approve USDC 0.01 to demo-merchant",
    message: "MandateRail spend approval: 0.01 USDC → demo-merchant",
  },
  {
    id: "pending-demo-2",
    status: "pending",
    createdAt: new Date(now - 2 * 60 * 1000).toISOString(),
    mandateId: "mandate-demo-2",
    sig_hint: "sign-mandate",
    display_hint: "Sign draft mandate mandate-demo-2",
    message: "Sign IntentMandate mandate-demo-2",
  },
];

export function mutatePending(
  id: string,
  status: "approved" | "rejected",
): PendingApproval | null {
  const item = mockPending.find((p) => p.id === id);
  if (!item) return null;
  item.status = status;
  if (status === "approved") {
    item.signature = "sig_mock_approved";
    item.address = DEMO_PRINCIPAL;
  }
  return item;
}

export function mutateRevoke(id: string): IntentMandate | null {
  const m = mockMandates.find((x) => x.id === id);
  if (!m) return null;
  m.revoked = true;
  return m;
}

/**
 * v11 app-derived fields (docs/ops/attested-release-signer.md §2.1): the app stores the exact signed bytes it
 * submitted, and derives tx_id / first_valid / last_valid / group_id / sender from those same bytes here.
 * The signer and the CLI re-derive them independently from the stored bytes (echo checks).
 *
 * kind 'xpayment': one canonical msgpack SignedTransaction (the payer's payment).
 * kind 'group':    canonical SignedTransactions concatenated (the atomic group); the spend's payment is the one
 *                  sent by `payer`. Every element must be canonical (re-encoding must reproduce the bytes).
 */
import algosdk from "algosdk";

export type SignedTxnKind = "xpayment" | "group";
export interface DerivedTxn {
  txId: string;
  firstValid: number;
  lastValid: number;
  groupId: string; // base64 or "" when ungrouped
  sender: string;
  genesisHash: string; // base64
  type: string;
  receiver: string | null;
  assetId: number | null; // null for ALGO pay
  amount: bigint;
  fee: bigint;
  closeTo: string | null;
  rekeyTo: string | null;
  lease: boolean;
}
export class SignedTxnError extends Error {}

export const MAX_SIGNED_TXN_BYTES = 16384;
const MAX_GROUP = 16;

/** Splits canonical concatenated SignedTransactions; throws on any non-canonical or trailing byte. */
export function splitSignedTxns(bytes: Uint8Array): algosdk.SignedTransaction[] {
  if (bytes.length < 1 || bytes.length > MAX_SIGNED_TXN_BYTES) throw new SignedTxnError("signed_txn size");
  const out: algosdk.SignedTransaction[] = [];
  let off = 0;
  while (off < bytes.length) {
    if (out.length >= MAX_GROUP) throw new SignedTxnError("too many transactions");
    let st: algosdk.SignedTransaction | undefined;
    let enc: Uint8Array | undefined;
    // msgpack has no length prefix: find the shortest prefix that decodes and re-encodes identically
    for (let end = off + 1; end <= bytes.length; end++) {
      const part = bytes.subarray(off, end);
      try {
        st = algosdk.decodeSignedTransaction(part);
        enc = algosdk.encodeMsgpack(st);
        if (enc.length === part.length && Buffer.from(enc).equals(Buffer.from(part))) break;
      } catch {
        /* incomplete prefix */
      }
      st = undefined;
    }
    if (!st || !enc) throw new SignedTxnError("signed_txn is not canonical msgpack SignedTransactions");
    out.push(st);
    off += enc.length;
  }
  return out;
}

function derive(st: algosdk.SignedTransaction): DerivedTxn {
  const t = st.txn;
  const axfer = t.assetTransfer;
  const pay = t.payment;
  const z = (a: algosdk.Address | undefined) => (a && a.toString() !== algosdk.ALGORAND_ZERO_ADDRESS_STRING ? a.toString() : null);
  return {
    txId: t.txID(),
    firstValid: Number(t.firstValid),
    lastValid: Number(t.lastValid),
    groupId: t.group && t.group.some((b) => b !== 0) ? Buffer.from(t.group).toString("base64") : "",
    sender: t.sender.toString(),
    genesisHash: Buffer.from(t.genesisHash ?? new Uint8Array()).toString("base64"),
    type: String(t.type),
    receiver: axfer ? axfer.receiver.toString() : pay ? pay.receiver.toString() : null,
    assetId: axfer ? Number(axfer.assetIndex) : null,
    amount: axfer ? axfer.amount : pay ? pay.amount : 0n,
    fee: t.fee,
    closeTo: axfer ? z(axfer.closeRemainderTo) : pay ? z(pay.closeRemainderTo) : null,
    rekeyTo: z(t.rekeyTo),
    lease: !!t.lease && t.lease.some((b) => b !== 0),
  };
}

/** Derives the spend's fields from the stored bytes. `payer` picks the payment in a group. */
export function deriveSignedTxn(bytes: Uint8Array, kind: SignedTxnKind, payer?: string): DerivedTxn & { all: DerivedTxn[] } {
  const all = splitSignedTxns(bytes).map(derive);
  if (kind === "xpayment") {
    // the X-PAYMENT payload: the payer's payment alone, or payer + (unsigned) fee-payer member of one group
    if (all.length === 1) {
      if (all[0]!.groupId !== "") throw new SignedTxnError("single xpayment member must be ungrouped");
      return { ...all[0]!, all };
    }
    if (all.length !== 2) throw new SignedTxnError("xpayment: 1 or 2 members");
  } else if (all.length < 2) {
    throw new SignedTxnError("group needs >= 2 transactions");
  }
  const g = all[0]!.groupId;
  if (!g || all.some((d) => d.groupId !== g)) throw new SignedTxnError("group ids differ or are missing");
  const mine = all.filter((d) => (payer ? d.sender === payer : true) && (d.type === "axfer" || d.type === "pay"));
  if (mine.length !== 1) throw new SignedTxnError("group must hold exactly one payment from the payer");
  return { ...mine[0]!, all };
}

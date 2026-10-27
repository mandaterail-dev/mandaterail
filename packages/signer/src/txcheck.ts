/**
 * §2.1 steps 1-6: the signer re-derives and checks everything from the stored signed bytes itself.
 */
import { createPublicKey, verify as edVerify } from "node:crypto";
import algosdk from "algosdk";
import { splitSignedTxns, type SignedTxnKind } from "@mandaterail/storage";
import type { SignerConfig } from "./config.js";

export class TxCheckError extends Error {}
export interface TxFacts {
  txId: string; firstValid: number; lastValid: number; groupId: string; sender: string; amountMicro: bigint;
  /** every member txId: the absence checks cover all of them (§2.1 "Which txId is attested"). */
  memberTxIds: string[];
}

const ED_SPKI = Buffer.from("302a300506032b6570032100", "hex");
function sigOk(st: algosdk.SignedTransaction): boolean {
  if (st.lsig || st.msig || (st as { pqsig?: unknown }).pqsig) return false; // none pinned: refused
  if (!st.sig || st.sig.length !== 64) return false;
  const pk = createPublicKey({ key: Buffer.concat([ED_SPKI, Buffer.from(st.txn.sender.publicKey)]), format: "der", type: "spki" });
  if (st.sgnr && st.sgnr.toString() !== st.txn.sender.toString()) return false; // rekeyed accounts refused
  return edVerify(null, Buffer.from(st.txn.bytesToSign()), pk, Buffer.from(st.sig));
}
const zero = (a?: algosdk.Address) => !a || a.toString() === algosdk.ALGORAND_ZERO_ADDRESS_STRING;
const noLease = (t: algosdk.Transaction) => !t.lease || t.lease.every((b) => b === 0);

export function checkSignedTxn(bytes: Uint8Array, kind: SignedTxnKind, c: SignerConfig): TxFacts {
  let sts: algosdk.SignedTransaction[];
  try {
    sts = splitSignedTxns(bytes); // canonical msgpack only, no trailing bytes
  } catch (e) {
    throw new TxCheckError(`decode: ${(e as Error).message}`);
  }
  const gh = c.genesisHash;
  for (const st of sts) {
    const t = st.txn;
    if (Buffer.from(t.genesisHash ?? new Uint8Array()).toString("base64") !== gh) throw new TxCheckError("genesis hash is not the network pin");
    if (!(t.firstValid < t.lastValid && t.lastValid <= t.firstValid + 1000n)) throw new TxCheckError("valid window");
    if (!zero(t.rekeyTo) || !noLease(t)) throw new TxCheckError("rekey / lease refused");
  }
  const pays = sts.filter((s) => s.txn.sender.toString() === c.payer);
  if (pays.length !== 1) throw new TxCheckError("exactly one member from the pinned payer");
  const p = pays[0]!;
  const ax = p.txn.assetTransfer;
  if (p.txn.type !== algosdk.TransactionType.axfer || !ax) throw new TxCheckError("payment must be axfer");
  if (Number(ax.assetIndex) !== c.usdcAsaId) throw new TxCheckError("asset is not the pinned USDC");
  if (ax.receiver.toString() !== c.merchant) throw new TxCheckError("receiver is not the pinned merchant");
  if (!zero(ax.closeRemainderTo) || !zero(ax.assetSender)) throw new TxCheckError("close / clawback refused");
  if (ax.amount > c.policy.maxAmountMicro) throw new TxCheckError("amount above the cap");
  if (!sigOk(p)) throw new TxCheckError("payer signature does not verify");
  const others = sts.filter((s) => s !== p);
  if (kind === "xpayment") {
    if (sts.length !== 1 && sts.length !== 2) throw new TxCheckError("xpayment: 1 or 2 members");
  } else if (sts.length !== 2) {
    throw new TxCheckError("group: exactly payer + fee-payer");
  }
  if (sts.length === 2) {
    if (p.txn.fee !== 0n) throw new TxCheckError("payer fee must be 0 in a pooled group");
    const f = others[0]!;
    const fp = f.txn.payment;
    if (!c.feePayer || f.txn.type !== algosdk.TransactionType.pay || !fp || f.txn.sender.toString() !== c.feePayer
        || fp.receiver.toString() !== c.feePayer || fp.amount !== 0n || !zero(fp.closeRemainderTo) || f.txn.fee > c.feePayerMaxFee) {
      throw new TxCheckError("fee-payer member is not the pinned pattern");
    }
    if (kind === "group" && !sigOk(f)) throw new TxCheckError("fee-payer signature does not verify");
    // the group id is computed over the members WITHOUT their grp field
    const bare = sts.map((s) => {
      const c = algosdk.decodeUnsignedTransaction(algosdk.encodeUnsignedTransaction(s.txn));
      (c as unknown as { group: Uint8Array | undefined }).group = undefined;
      return c;
    });
    const gid = algosdk.computeGroupID(bare);
    for (const s of sts) if (!s.txn.group || !Buffer.from(s.txn.group).equals(Buffer.from(gid))) throw new TxCheckError("group id mismatch");
  } else {
    if (p.txn.group && p.txn.group.some((b) => b !== 0)) throw new TxCheckError("single member must be ungrouped");
    if (p.txn.fee > c.payerMaxFee) throw new TxCheckError("payer fee above the cap"); // R43-P3
  }
  return {
    txId: p.txn.txID(),
    firstValid: Number(p.txn.firstValid),
    lastValid: Number(p.txn.lastValid),
    groupId: p.txn.group && p.txn.group.some((b) => b !== 0) ? Buffer.from(p.txn.group).toString("base64") : "",
    sender: c.payer,
    amountMicro: ax.amount,
    memberTxIds: sts.map((s) => s.txn.txID()),
  };
}

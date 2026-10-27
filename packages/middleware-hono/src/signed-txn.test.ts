/** v11 launch blocker (R43): the middleware stores the exact X-PAYMENT bytes before settle, fail closed. */
import { describe, expect, it } from "vitest";
import algosdk from "algosdk";
import { InMemorySpendStore, toMicro } from "@mandaterail/core";
import { settleWithReservation, xpaymentSignedBytes } from "./index.js";

const payer = algosdk.generateAccount();
const feePayer = algosdk.generateAccount();
const merchant = algosdk.generateAccount();
function group() {
  const sp = { fee: 0n, minFee: 1000n, firstValid: 500n, lastValid: 1500n, genesisHash: new Uint8Array(32), genesisID: "testnet-v1.0", flatFee: true };
  const pay = algosdk.makeAssetTransferTxnWithSuggestedParamsFromObject({ sender: payer.addr, receiver: merchant.addr, amount: 10_000n, assetIndex: 10458941, suggestedParams: sp });
  const fee = algosdk.makePaymentTxnWithSuggestedParamsFromObject({ sender: feePayer.addr, receiver: feePayer.addr, amount: 0n, suggestedParams: { ...sp, fee: 2000n } });
  algosdk.assignGroupID([fee, pay]);
  const payload = { x402Version: 2, scheme: "exact", network: "x", payload: { paymentIndex: 1, paymentGroup: [
    Buffer.from(algosdk.encodeUnsignedTransaction(fee)).toString("base64"), Buffer.from(pay.signTxn(payer.sk)).toString("base64"),
  ] } };
  return { payload, payTxId: pay.txID() };
}
const fac = (settleOk = true) => ({
  verify: async () => ({ ok: true as const, status: 200, data: {} }),
  settle: async () => (settleOk ? { ok: true as const, status: 200, data: { transaction: "T" } } : { ok: false as const, status: 502, error: "x" }),
}) as never;

class SignedStore extends InMemorySpendStore {
  stored: { bytes: Uint8Array; submitRound: number } | null = null;
  fail = false;
  attachSignedTxn(_id: string, i: { signedTxn: Uint8Array; submitRound: number }) {
    if (this.fail) return null;
    this.stored = { bytes: i.signedTxn, submitRound: i.submitRound };
    // what PgSpendStore does: derive from the bytes (here: the payer's member)
    let off = 0;
    const out: algosdk.SignedTransaction[] = [];
    while (off < i.signedTxn.length) {
      for (let end = off + 1; end <= i.signedTxn.length; end++) {
        try { const st = algosdk.decodeSignedTransaction(i.signedTxn.subarray(off, end)); if (algosdk.encodeMsgpack(st).length === end - off) { out.push(st); off = end; break; } } catch { /* more */ }
        if (end === i.signedTxn.length) throw new Error("bad");
      }
    }
    const p = out.find((s) => s.txn.sender.toString() === payer.addr.toString())!;
    return { txId: p.txn.txID(), lastValid: Number(p.txn.lastValid) };
  }
}
const reserve = async (s: InMemorySpendStore) => {
  await s.reserve({ id: "r1", payer: payer.addr.toString(), amountMicro: 10_000n, caps: { perPaymentMicro: toMicro("1"), perDayMicro: toMicro("5") }, nowMs: Date.now() });
};

describe("middleware stores signed_txn before settle", () => {
  it("wraps the unsigned fee-payer member, keeps signed bytes exact, submit round = firstValid, settles", async () => {
    const g = group();
    const x = xpaymentSignedBytes(g.payload as never)!;
    expect(x.firstValid).toBe(500);
    const store = new SignedStore();
    await reserve(store);
    const r = await settleWithReservation({ facilitator: fac(), paymentPayload: g.payload as never, requirements: {} as never, store, reservationId: "r1" });
    expect(r.kind).toBe("settled");
    expect(Buffer.from(store.stored!.bytes).equals(Buffer.from(x.bytes))).toBe(true);
    expect(store.stored!.submitRound).toBe(500);
    expect(store.get("r1")).toMatchObject({ status: "settled" });
  });
  it("attach failure -> released, never settled (fail closed)", async () => {
    const g = group();
    const store = new SignedStore();
    store.fail = true;
    await reserve(store);
    let settled = false;
    const f = { verify: async () => ({ ok: true, status: 200, data: {} }), settle: async () => { settled = true; return { ok: true, status: 200, data: {} }; } } as never;
    const r = await settleWithReservation({ facilitator: f, paymentPayload: g.payload as never, requirements: {} as never, store, reservationId: "r1" });
    expect(r.kind).toBe("reservation_error");
    expect(settled).toBe(false);
    expect(store.get("r1")).toMatchObject({ status: "released" });
  });
  it("undecodable or non-canonical members -> null", () => {
    expect(xpaymentSignedBytes({ payload: { paymentGroup: ["AAAA"] } } as never)).toBeNull();
    expect(xpaymentSignedBytes({ payload: { paymentGroup: [] } } as never)).toBeNull();
  });
});

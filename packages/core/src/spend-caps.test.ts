import { TESTNET_PROFILE, MAINNET_PROFILE } from "./network.js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import algosdk from "algosdk";
import type { IntentMandate } from "@mandaterail/schema";
import {
  checkSpendCaps,
  evaluateMandate,
  fromMicro,
  InMemorySpendStore,
  reconcileSpend,
  indexerTxCheck,
  resolveSpendCaps,
  signMandate,
  SpendCapConfigError,
  toMicro,
  utcDayStartMs,
} from "./index.js";
const IDX_TP = { ...TESTNET_PROFILE, providerAllowlist: [{ host: "idx.example", operator: "test" }] };

const NOW = Date.parse("2026-10-15T15:00:00Z");
const caps = resolveSpendCaps({});
let n = 0;
describe("T7 spend caps: config", () => {
  it("defaults = hard maxima 1 / 5 USDC", () => {
    expect(fromMicro(caps.perPaymentMicro)).toBe("1.000000");
    expect(fromMicro(caps.perDayMicro)).toBe("5.000000");
  });
  it("env may lower, never raise", () => {
    const c = resolveSpendCaps({ SPEND_CAP_PER_PAYMENT_USDC: "0.25", SPEND_CAP_PER_DAY_USDC: "0.05" + "0" });
    expect(c.perPaymentMicro).toBe(50_000n); // clamped to the lowered daily cap
    expect(c.perDayMicro).toBe(50_000n);
    expect(resolveSpendCaps({ SPEND_CAP_PER_PAYMENT_USDC: "0.25" }).perPaymentMicro).toBe(250_000n);
    expect(() => resolveSpendCaps({ SPEND_CAP_PER_PAYMENT_USDC: "1.01" })).toThrow(SpendCapConfigError);
    expect(() => resolveSpendCaps({ SPEND_CAP_PER_DAY_USDC: "5.000001" })).toThrow(SpendCapConfigError);
    expect(() => resolveSpendCaps({ SPEND_CAP_PER_DAY_USDC: "0" })).toThrow(SpendCapConfigError);
    expect(() => resolveSpendCaps({ SPEND_CAP_PER_DAY_USDC: "1e1" })).toThrow(SpendCapConfigError);
  });
  it("micro conversion is exact (no float drift)", () => {
    expect(toMicro("0.1") + toMicro("0.2")).toBe(toMicro("0.3"));
    expect(() => toMicro("-1")).toThrow();
    expect(() => toMicro("0.0000001")).toThrow();
  });
});

describe("T7 spend store: reserve / finalize / reconcile", () => {
  const settle = (st: InMemorySpendStore, payer: string, amount: string, at = NOW - 1000) =>
    st.recordSettled({ id: `s-${++n}`, payer, amountMicro: toMicro(amount), createdMs: at });

  it("per-payment: 1.00 ok, 1.000001 denied", async () => {
    const store = new InMemorySpendStore();
    expect((await checkSpendCaps({ payer: "P", amountMicro: toMicro("1.00"), caps, store, nowMs: NOW })).ok).toBe(true);
    expect(await checkSpendCaps({ payer: "P", amountMicro: toMicro("1.000001"), caps, store, nowMs: NOW })).toMatchObject({ ok: false, reason: "per_payment_cap_exceeded" });
  });
  it("per day per payer: today only, per payer; pending counts", async () => {
    const store = new InMemorySpendStore();
    for (let i = 0; i < 4; i++) settle(store, "P", "1.00");
    settle(store, "P", "1.00", utcDayStartMs(NOW) - 1); // yesterday
    settle(store, "Q", "1.00");
    expect(store.spentSinceMicro("P", utcDayStartMs(NOW))).toBe(toMicro("4"));
    const r = await checkSpendCaps({ payer: "P", amountMicro: toMicro("0.5"), caps, store, nowMs: NOW });
    expect(r.ok).toBe(true);
    // the pending 0.5 already counts
    expect(await checkSpendCaps({ payer: "P", amountMicro: toMicro("0.500001"), caps, store, nowMs: NOW })).toMatchObject({ ok: false, reason: "daily_cap_exceeded" });
    expect((await checkSpendCaps({ payer: "P", amountMicro: toMicro("0.5"), caps, store, nowMs: NOW })).ok).toBe(true);
    const tomorrow = utcDayStartMs(NOW) + 86_400_000;
    expect((await checkSpendCaps({ payer: "P", amountMicro: toMicro("1"), caps, store, nowMs: tomorrow })).ok).toBe(true);
  });
  it("released frees the amount; settled and ambiguous keep it counted", async () => {
    const store = new InMemorySpendStore();
    const ids: string[] = [];
    for (let i = 0; i < 5; i++) {
      const r = await checkSpendCaps({ payer: "P", amountMicro: toMicro("1"), caps, store, nowMs: NOW });
      if (!r.ok) throw new Error("unexpected");
      ids.push(r.reservationId!);
    }
    expect((await checkSpendCaps({ payer: "P", amountMicro: 1n, caps, store, nowMs: NOW })).ok).toBe(false);
    expect(store.finalize(ids[0]!, "released", NOW)).toBe(true);
    expect(store.finalize(ids[0]!, "settled", NOW)).toBe(false); // CAS: only from pending
    expect(store.finalize(ids[1]!, "settled", NOW, "TX1")).toBe(true);
    expect(store.finalize(ids[2]!, "ambiguous", NOW)).toBe(true);
    expect(store.spentSinceMicro("P", utcDayStartMs(NOW))).toBe(toMicro("4"));
    // reconcile: ambiguous -> released frees it; settled can't be reconciled away
    expect(store.reconcile(ids[2]!, "released", NOW)).toBe(true);
    expect(store.reconcile(ids[1]!, "released", NOW)).toBe(false);
    expect(store.spentSinceMicro("P", utcDayStartMs(NOW))).toBe(toMicro("3"));
  });
  it("reconcileSpend: chain says settled / released / unknown; stale pending included", async () => {
    const store = new InMemorySpendStore();
    const mk = async (payer: string, at: number) => {
      const r = await checkSpendCaps({ payer, amountMicro: toMicro("1"), caps, store, nowMs: at });
      return r.ok ? r.reservationId! : "";
    };
    const a = await mk("A", NOW); store.finalize(a, "ambiguous", NOW, null);
    const b = await mk("B", NOW); store.finalize(b, "ambiguous", NOW, "TXB");
    const c = await mk("C", NOW - 3600_000); // crashed process, still pending
    const d = await mk("D", NOW); // fresh pending: not touched
    const out = await reconcileSpend(store, async (r) => (r.id === b ? "settled" : r.id === c ? "released" : "unknown"), { nowMs: NOW, pendingOlderThanMs: 900_000 });
    expect(out).toEqual({ settled: 1, released: 1, unknown: 1 });
    expect(store.get(a)!.status).toBe("ambiguous");
    expect(store.get(b)!.status).toBe("settled");
    expect(store.get(c)!.status).toBe("released");
    expect(store.get(d)!.status).toBe("pending");
  });
  it("indexerTxCheck: confirmed -> settled; missing past lastValid -> released; else unknown", async () => {
    let idxRound = 1000;
    let genesis: object = { "genesis-id": "testnet-v1.0", "genesis-hash": TESTNET_PROFILE.caip2.slice(9) };
    const f = (async (url: string) => {
      if (url.endsWith("/health")) return new Response(JSON.stringify({ round: idxRound }), { status: 200 });
      if (url.endsWith("/v2/blocks/0")) return new Response(JSON.stringify(genesis), { status: 200 });
      if (url.endsWith("/TXOK")) return new Response(JSON.stringify({ transaction: { "confirmed-round": 5 } }), { status: 200 });
      if (url.endsWith("/TXERR")) return new Response("", { status: 500 });
      return new Response("{}", { status: 404 });
    }) as unknown as typeof fetch;
    const chk = indexerTxCheck("https://idx.example/", f, { profile: IDX_TP, unsafeTestCustomFetch: true });
    const base = { id: "x", payer: "P", amountMicro: 1n, status: "ambiguous" as const, createdMs: 0, updatedMs: 0, lastValid: 995 };
    expect(await chk({ ...base, txId: "TXOK" })).toBe("settled");
    expect(await chk({ ...base, txId: "TXNO" })).toBe("unknown"); // 1000 <= 995 + 10
    idxRound = 1006;
    expect(await chk({ ...base, txId: "TXNO" })).toBe("released");
    expect(await chk({ ...base, txId: "TXNO", lastValid: null })).toBe("unknown");
    expect(await chk({ ...base, txId: "TXERR" })).toBe("unknown");
    expect(await chk({ ...base, txId: null })).toBe("unknown");
    // R20-P3-2: a wrong-network indexer never yields "released"
    genesis = { "genesis-id": "mainnet-v1.0", "genesis-hash": MAINNET_PROFILE.caip2.slice(9) };
    const chk2 = indexerTxCheck("https://idx.example/", f, { profile: IDX_TP, unsafeTestCustomFetch: true });
    expect(await chk2({ ...base, txId: "TXNO" })).toBe("unknown");
    expect(() => indexerTxCheck("https://idx.example/", f, { profile: IDX_TP, unsafeTestCustomFetch: true, marginRounds: -1 })).toThrow(/non-negative integer/);
  });
  it("fails closed when the store is missing or errors", async () => {
    expect(await checkSpendCaps({ payer: "P", amountMicro: 1n, caps, nowMs: NOW })).toMatchObject({ ok: false, reason: "spend_ledger_unavailable" });
    const broken = new InMemorySpendStore();
    broken.reserve = () => { throw new Error("db down"); };
    expect(await checkSpendCaps({ payer: "P", amountMicro: 1n, caps, store: broken, nowMs: NOW })).toMatchObject({ ok: false, reason: "spend_ledger_unavailable" });
  });
});

describe("T7 spend caps: policy engine", () => {
  const prev = process.env.DEV_ALLOW_UNSIGNED;
  beforeEach(() => { process.env.DEV_ALLOW_UNSIGNED = "false"; });
  afterEach(() => { if (prev === undefined) delete process.env.DEV_ALLOW_UNSIGNED; else process.env.DEV_ALLOW_UNSIGNED = prev; });

  function mandate(maxAmount = "10.00"): IntentMandate {
    const acct = algosdk.generateAccount();
    const u = {
      id: "m-cap", principal: acct.addr.toString(), agent: "did:example:a", maxAmount, asset: "USDC",
      allowlist: ["demo-merchant"], expiresAt: new Date(NOW + 3600_000).toISOString(), revoked: false,
      nonce: "n", createdAt: new Date(NOW).toISOString(),
    };
    return { ...u, signature: signMandate(u as Omit<IntentMandate, "signature">, acct.sk) } as IntentMandate;
  }
  const base = { asset: "USDC", merchantId: "demo-merchant", now: new Date(NOW) };

  it("per-payment cap applies even when the mandate allows more", async () => {
    const r = await evaluateMandate(mandate(), { ...base, amount: "2.00", spend: { caps } });
    expect(r).toMatchObject({ ok: false, reason: "per_payment_cap_exceeded" });
    expect((await evaluateMandate(mandate(), { ...base, amount: "1.00", spend: { caps } })).ok).toBe(true);
  });
  it("daily cap per payer from the receipts store", async () => {
    const m = mandate();
    const store = new InMemorySpendStore();
    for (let i = 0; i < 5; i++) {
      const r = await evaluateMandate(m, { ...base, amount: "1.00", spend: { caps, store } });
      expect(r.ok).toBe(true);
      if (r.ok) expect(store.get(r.spendReservationId!)!.status).toBe("pending");
    }
    const r = await evaluateMandate(m, { ...base, amount: "0.01", spend: { caps, store } });
    expect(r).toMatchObject({ ok: false, reason: "daily_cap_exceeded" });
    // another payer is unaffected
    expect((await evaluateMandate(mandate(), { ...base, amount: "1.00", spend: { caps, store } })).ok).toBe(true);
  });
  it("requireLedger (MainNet) denies without a ledger", async () => {
    const r = await evaluateMandate(mandate(), { ...base, amount: "0.01", spend: { caps, requireLedger: true } });
    expect(r).toMatchObject({ ok: false, reason: "spend_ledger_unavailable" });
  });
  it("caps run after the signature check (no ledger probing by forged mandates)", async () => {
    const m = { ...mandate(), maxAmount: "9.00" };
    let asked = false;
    const store = new InMemorySpendStore();
    const orig = store.reserve.bind(store);
    store.reserve = (i) => { asked = true; return orig(i); };
    const r = await evaluateMandate(m, { ...base, amount: "0.01", spend: { caps, store } });
    expect(r.ok).toBe(false);
    expect(asked).toBe(false);
  });
  it("no spend context -> Phase-1 behaviour unchanged", async () => {
    expect((await evaluateMandate(mandate(), { ...base, amount: "9.00" })).ok).toBe(true);
  });
});

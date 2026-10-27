import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Hono } from "hono";
import algosdk from "algosdk";
import type { IntentMandate } from "@mandaterail/schema";
import {
  ALGORAND_MAINNET_CAIP2,
  InMemorySpendStore,
  signMandate,
  toMicro,
  utcDayStartMs,
} from "@mandaterail/core";
import { buildPaymentRequirements, mandateRail, type MandatePaymentConfig } from "./index.js";

const KEYS = ["NETWORK", "USDC_ASA_ID", "ALLOW_MAINNET", "FEE_PAYER", "DEV_ALLOW_UNSIGNED", "SPEND_CAP_PER_DAY_USDC", "SPEND_CAP_PER_PAYMENT_USDC"];
const saved: Record<string, string | undefined> = {};
beforeEach(() => { for (const k of KEYS) { saved[k] = process.env[k]; delete process.env[k]; } });
afterEach(() => { for (const k of KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; } });

const okFacilitator = {
  verify: async () => ({ ok: true as const, status: 200, data: {} }),
  settle: async () => ({ ok: true as const, status: 200, data: { transaction: `TX${Math.random()}` } }),
} as unknown as MandatePaymentConfig["facilitator"];

function signed(): IntentMandate {
  const a = algosdk.generateAccount();
  const u = {
    id: "m", principal: a.addr.toString(), agent: "did:example:a", maxAmount: "10.00", asset: "USDC",
    allowlist: ["shop"], expiresAt: new Date(Date.now() + 3600_000).toISOString(), revoked: false,
    nonce: "n", createdAt: new Date().toISOString(),
  };
  return { ...u, signature: signMandate(u as Omit<IntentMandate, "signature">, a.sk) } as IntentMandate;
}

type Fac = NonNullable<MandatePaymentConfig["facilitator"]>;
function appFor(
  amount: string,
  mandate: IntentMandate,
  store: InMemorySpendStore,
  extra: Partial<MandatePaymentConfig> = {},
  handler: () => Promise<void> = async () => undefined,
) {
  const app = new Hono();
  app.onError((e, c) => c.json({ error: "handler_failed", message: e.message }, 500));
  app.get(
    "/paid",
    mandateRail({
      merchantId: "shop", amount, asset: "USDC", payTo: "PAYTO",
      loadMandate: async () => mandate,
      facilitator: okFacilitator,
      parsePayment: () => ({ x402Version: 2 }) as never,
      spend: { store },
      ...extra,
    }),
    async (c) => {
      await handler();
      return c.json({ ok: true });
    },
  );
  return app;
}
const spent = (store: InMemorySpendStore, m: IntentMandate) => store.spentSinceMicro(m.principal, utcDayStartMs(Date.now()));
const pay = (app: Hono) => app.request("/paid", { headers: { "x-payment": JSON.stringify({ x402Version: 2, payload: {} }) } });

describe("T5 requirements follow networkProfile()", () => {
  it("TestNet default ASA; MainNet USDC 31566704 and explicit fee payer", () => {
    const base = { merchantId: "s", amount: "0.01", asset: "USDC", payTo: "P", loadMandate: async () => null };
    expect(buildPaymentRequirements(base).asset).toBe("10458941");
    process.env.NETWORK = "mainnet";
    expect(() => buildPaymentRequirements(base)).toThrow(/FEE_PAYER/);
    process.env.FEE_PAYER = "FEEPAYER";
    const r = buildPaymentRequirements(base);
    expect(r).toMatchObject({ asset: "31566704", network: ALGORAND_MAINNET_CAIP2 });
    expect(() => buildPaymentRequirements({ ...base, assetId: "10458941" })).toThrow(/31566704/);
  });
});

describe("T7 caps enforced by the middleware", () => {
  it("per payment: 1.01 USDC denied before verify/settle", async () => {
    const res = await pay(appFor("1.01", signed(), new InMemorySpendStore()));
    expect(res.status).toBe(403);
    expect(((await res.json()) as any).reason).toBe("per_payment_cap_exceeded");
  });
  it("per day per payer: sixth 1-USDC payment denied; settled rows carry the txId", async () => {
    const store = new InMemorySpendStore();
    const m = signed();
    const app = appFor("1.00", m, store);
    for (let i = 0; i < 5; i++) expect((await pay(app)).status).toBe(200);
    const res = await pay(app);
    expect(res.status).toBe(403);
    expect(((await res.json()) as any).reason).toBe("daily_cap_exceeded");
    expect(store.listUnresolved(Date.now(), 0, 10)).toHaveLength(0);
  });
  it("concurrent requests cannot overshoot (reservation written before settle)", async () => {
    process.env.SPEND_CAP_PER_DAY_USDC = "0.05";
    const app = appFor("0.01", signed(), new InMemorySpendStore());
    const codes = (await Promise.all(Array.from({ length: 12 }, () => pay(app)))).map((r) => r.status);
    expect(codes.filter((c) => c === 200)).toHaveLength(5);
    expect(codes.filter((c) => c === 403)).toHaveLength(7);
  });
  it("failed handler after settle: still counted as spent", async () => {
    const store = new InMemorySpendStore();
    const m = signed();
    const app = appFor("1.00", m, store, {}, async () => { throw new Error("handler blew up"); });
    expect((await pay(app)).status).toBe(500);
    expect(spent(store, m)).toBe(toMicro("1"));
  });
  it("failed receipt write: still counted as spent (settled before the handler)", async () => {
    const store = new InMemorySpendStore();
    const m = signed();
    const app = appFor("1.00", m, store, {}, async () => { throw new Error("receipts store: ECONNRESET"); });
    for (let i = 0; i < 5; i++) await pay(app);
    expect(spent(store, m)).toBe(toMicro("5"));
    expect(((await (await pay(app)).json()) as any).reason).toBe("daily_cap_exceeded");
  });
  it("settle timeout: ambiguous, counted until reconciled", async () => {
    const store = new InMemorySpendStore();
    const m = signed();
    const hang = { ...okFacilitator, settle: () => new Promise(() => undefined) } as unknown as Fac;
    const app = appFor("1.00", m, store, { facilitator: hang, spend: { store, settleTimeoutMs: 30 } });
    const res = await pay(app);
    expect(res.status).toBe(502);
    expect(((await res.json()) as any).spend).toBe("ambiguous_until_reconciled");
    const [amb] = store.listUnresolved(Date.now(), 1e9, 10);
    expect(amb!.status).toBe("ambiguous");
    expect(spent(store, m)).toBe(toMicro("1"));
    store.reconcile(amb!.id, "released", Date.now());
    expect(spent(store, m)).toBe(0n);
  });
  it("settle error or throw: ambiguous; verify failure / bad payload: released", async () => {
    const store = new InMemorySpendStore();
    const m = signed();
    const bad = { ...okFacilitator, settle: async () => ({ ok: false, status: 500, error: "upstream" }) } as unknown as Fac;
    expect((await pay(appFor("1.00", m, store, { facilitator: bad }))).status).toBe(502);
    const throws = { ...okFacilitator, settle: async () => { throw new Error("socket hang up"); } } as unknown as Fac;
    expect((await pay(appFor("1.00", m, store, { facilitator: throws }))).status).toBe(502);
    expect(spent(store, m)).toBe(toMicro("2"));
    const noVerify = { ...okFacilitator, verify: async () => ({ ok: false, status: 400, error: "bad sig" }) } as unknown as Fac;
    expect((await pay(appFor("1.00", m, store, { facilitator: noVerify }))).status).toBe(402);
    expect((await pay(appFor("1.00", m, store, { parsePayment: () => null }))).status).toBe(400);
    expect(spent(store, m)).toBe(toMicro("2"));
  });
  it("MainNet refuses to build without a spend store", () => {
    process.env.NETWORK = "mainnet";
    process.env.FEE_PAYER = "FEEPAYER";
    expect(() => mandateRail({ merchantId: "s", amount: "0.01", asset: "USDC", payTo: "P", loadMandate: async () => null })).toThrow(/spend.store/);
  });
});

describe("R18-P3-2 txId pinned before settle", () => {
  function group() {
    const a = algosdk.generateAccount();
    const txn = algosdk.makeAssetTransferTxnWithSuggestedParamsFromObject({
      sender: a.addr, receiver: a.addr, assetIndex: 10458941, amount: 10000,
      suggestedParams: { fee: 1000, firstValid: 100, lastValid: 1100, genesisHash: new Uint8Array(32), genesisID: "testnet-v1.0", minFee: 1000, flatFee: true },
    });
    const signed = txn.signTxn(a.sk);
    return { txId: txn.txID(), payload: { x402Version: 2, scheme: "exact", network: "x", payload: { paymentGroup: [Buffer.from(signed).toString("base64")], paymentIndex: 0 } } };
  }
  it("pending row carries the group's first txId + lastValid before settle; kept on ambiguous", async () => {
    const store = new InMemorySpendStore();
    const m = signed();
    const g = group();
    let seenAtSettle: unknown;
    const hang = {
      ...okFacilitator,
      settle: () => {
        seenAtSettle = store.listUnresolved(Date.now(), 0, 10)[0];
        return new Promise(() => undefined);
      },
    } as unknown as Fac;
    const app = appFor("1.00", m, store, { facilitator: hang, parsePayment: () => g.payload as never, spend: { store, settleTimeoutMs: 20 } });
    expect((await pay(app)).status).toBe(502);
    expect(seenAtSettle).toMatchObject({ status: "pending", txId: g.txId, lastValid: 1100 });
    expect(store.listUnresolved(Date.now(), 1e9, 10)[0]).toMatchObject({ status: "ambiguous", txId: g.txId });
  });
  it("R19-P3-4: attachTxId failure (throw or false) aborts before settle, releases, 503", async () => {
    for (const mode of ["throw", "false"] as const) {
      const store = new InMemorySpendStore();
      store.attachTxId = (() => {
        if (mode === "throw") throw new Error("db down");
        return false;
      }) as never;
      const m = signed();
      const g = group();
      let settleCalls = 0;
      const fac = { ...okFacilitator, settle: async () => { settleCalls++; return { ok: true, status: 200, data: {} }; } } as unknown as Fac;
      const app = appFor("1.00", m, store, { facilitator: fac, parsePayment: () => g.payload as never });
      const res = await pay(app);
      expect(res.status).toBe(503);
      expect(await res.json()).toMatchObject({ error: "spend_ledger_unavailable" });
      expect(settleCalls).toBe(0);
      expect(spent(store, m)).toBe(0n);
    }
  });
  it("garbage group -> no txId (null), payment flow unaffected", async () => {
    const { paymentGroupFirstTxId } = await import("./index.js");
    expect(paymentGroupFirstTxId({ payload: { paymentGroup: ["%%%"], paymentIndex: 0 } } as never)).toBeNull();
    const g = group();
    expect(paymentGroupFirstTxId(g.payload as never)).toBe(g.txId);
    expect(paymentGroupFirstTxId(null)).toBeNull();
  });
});

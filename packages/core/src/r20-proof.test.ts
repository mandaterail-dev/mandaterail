// Upstream unit test for indexerNoConfirmProof (internal reviewer run 20; adapted
// from their local r20-proof.test.ts, now with genesis + margin + timeout).
import { describe, it, expect } from "vitest";
import { indexerNoConfirmProof, IndexerOptsError } from "./spend-caps.js";
import { MAINNET_PROFILE, TESTNET_PROFILE } from "./network.js";

const row = (o: Record<string, unknown> = {}) => ({ id: "r", payer: "P", amountMicro: 1n, status: "ambiguous", txId: "TX1", lastValid: 1000, createdMs: 0, updatedMs: 0, ...o }) as any;
const TN_GENESIS = { "genesis-id": "testnet-v1.0", "genesis-hash": TESTNET_PROFILE.caip2.slice(9) };
const MN_GENESIS = { "genesis-id": "mainnet-v1.0", "genesis-hash": MAINNET_PROFILE.caip2.slice(9) };
const P = { profile: TESTNET_PROFILE };

function f(tx: number | Error, health: number | Error | any = { round: 1011 }, genesis: number | Error | any = TN_GENESIS) {
  const calls: string[] = [];
  const fn = (async (u: string, init?: any) => {
    calls.push(u + " " + JSON.stringify(init?.headers ?? {}) + (init?.signal ? " signal" : ""));
    const reply = (v: any) => {
      if (v instanceof Error) throw v;
      if (typeof v === "number") return new Response("x", { status: v });
      return new Response(JSON.stringify(v), { status: 200 });
    };
    if (u.endsWith("/health")) return reply(health);
    if (u.endsWith("/v2/blocks/0")) return reply(genesis);
    if (tx instanceof Error) throw tx;
    return new Response("{}", { status: tx });
  }) as any;
  return { fn, calls };
}

describe("indexerNoConfirmProof", () => {
  it("404 + matching genesis + round > lastValid+margin => proof; token header + timeout signal sent", async () => {
    const { fn, calls } = f(404);
    expect(await indexerNoConfirmProof("http://i/", fn, { ...P, token: "T" })(row())).toMatchObject({ ok: true, round: 1011, marginRounds: 10 });
    expect(calls[0]).toContain("/v2/transactions/TX1");
    expect(calls.every((c) => c.includes('"X-Indexer-API-Token":"T"') && c.endsWith(" signal"))).toBe(true);
    expect(calls.some((c) => c.includes("/v2/blocks/0"))).toBe(true);
  });
  it("round == lastValid+margin => no proof", async () => { expect((await indexerNoConfirmProof("http://i", f(404, { round: 1010 }).fn, P)(row())).ok).toBe(false); });
  it("lagging indexer (low round) => no proof", async () => { expect((await indexerNoConfirmProof("http://i", f(404, { round: 500 }).fn, P)(row())).ok).toBe(false); });
  for (const s of [200, 500, 502, 503, 429, 401]) it(`tx status ${s} => no proof`, async () => { expect((await indexerNoConfirmProof("http://i", f(s).fn, P)(row())).ok).toBe(false); });
  it("network error => no proof", async () => { expect((await indexerNoConfirmProof("http://i", f(new Error("x")).fn, P)(row())).ok).toBe(false); });
  it("health 5xx / garbage / missing round => no proof", async () => {
    for (const h of [503, new Error("x"), {}, { round: "abc" }, { round: null }]) expect((await indexerNoConfirmProof("http://i", f(404, h).fn, P)(row())).ok).toBe(false);
  });
  it("no txId / no lastValid => no proof", async () => {
    expect((await indexerNoConfirmProof("http://i", f(404).fn, P)(row({ txId: null }))).ok).toBe(false);
    expect((await indexerNoConfirmProof("http://i", f(404).fn, P)(row({ lastValid: null }))).ok).toBe(false);
  });
  it("margin 0 => round lastValid+1 suffices", async () => { expect((await indexerNoConfirmProof("http://i", f(404, { round: 1001 }).fn, { ...P, marginRounds: 0 })(row())).ok).toBe(true); });
  it("R20-P3-3: negative / non-integer / NaN margin rejected by the library", () => {
    for (const m of [-5, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) expect(() => indexerNoConfirmProof("http://i", f(404).fn, { ...P, marginRounds: m })).toThrow(IndexerOptsError);
  });
  it("R20-P3-3: bad timeout rejected; a hung indexer times out => no proof", async () => {
    expect(() => indexerNoConfirmProof("http://i", f(404).fn, { ...P, timeoutMs: 0 })).toThrow(IndexerOptsError);
    const hang = ((_u: string, init?: { signal?: AbortSignal }) => new Promise((_res, rej) => init?.signal?.addEventListener("abort", () => rej(new Error("aborted"))))) as any;
    const t0 = Date.now();
    const r = await indexerNoConfirmProof("http://i", hang, { ...P, timeoutMs: 50 })(row());
    expect(r).toMatchObject({ ok: false, why: expect.stringMatching(/timed out/) });
    expect(Date.now() - t0).toBeLessThan(2000);
  });
  it("R20-P3-2: wrong-network / unreadable / partial genesis => no proof", async () => {
    for (const g of [MN_GENESIS, { ...TN_GENESIS, "genesis-id": "betanet-v1.0" }, { "genesis-id": "testnet-v1.0" }, 404, new Error("x"), {}]) {
      const r = await indexerNoConfirmProof("http://i", f(404, { round: 5000 }, g).fn, P)(row());
      expect(r.ok).toBe(false);
    }
    expect(await indexerNoConfirmProof("http://i", f(404, { round: 5000 }, MN_GENESIS).fn, { profile: MAINNET_PROFILE })(row())).toMatchObject({ ok: true });
  });
  it("profile is required", () => { expect(() => indexerNoConfirmProof("http://i", f(404).fn, {} as any)).toThrow(/profile/); });
  // R21-P3-4: the health round must be a JSON integer; a string is no longer coerced.
  it("round as string '1011' is rejected (R21-P3-4)", async () => { expect(await indexerNoConfirmProof("http://i", f(404, { round: "1011" }).fn, P)(row())).toMatchObject({ ok: false, why: "indexer round unknown" }); });
});

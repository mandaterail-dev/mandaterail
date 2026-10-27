/** R24-P2-1: twoProviderNoConfirmProof (two independent, genesis-checked providers). */
import { describe, expect, it } from "vitest";
import { MAINNET_PROFILE, TESTNET_PROFILE } from "./network.js";
import { IndexerOptsError, twoProviderNoConfirmProof, type SpendReservation } from "./spend-caps.js";

const TN = TESTNET_PROFILE.caip2.slice(9);
type Routes = Record<string, { status: number; body?: unknown }>;
function fakeFetch(hosts: Record<string, Routes>): typeof fetch {
  return (async (input: string | URL) => {
    const u = new URL(String(input));
    const r = hosts[u.host]?.[u.pathname];
    if (!r) return new Response("{}", { status: 404 });
    return new Response(JSON.stringify(r.body ?? {}), { status: r.status });
  }) as typeof fetch;
}
const idx = (round: number, tx: number, gh = TN, gid = "testnet-v1.0"): Routes => ({
  "/v2/blocks/0": { status: 200, body: { "genesis-id": gid, "genesis-hash": gh } },
  "/health": { status: 200, body: { round } },
  "/v2/transactions/TX1": { status: tx },
});
const algod = (round: number, pending: number, gh = TN): Routes => ({
  "/versions": { status: 200, body: { genesis_hash_b64: gh, genesis_id: "testnet-v1.0" } },
  "/v2/status": { status: 200, body: { "last-round": round } },
  "/v2/transactions/pending/TX1": { status: pending },
});
const row = { id: "r", payer: "P", amountMicro: 1n, status: "ambiguous", createdMs: 0, updatedMs: 0, txId: "TX1", lastValid: 1000 } as SpendReservation;
const A = { url: "https://idx-a.example", kind: "indexer" as const };
const B = { url: "https://idx-b.example", kind: "indexer" as const };
const G = { url: "https://algod-c.example", kind: "algod" as const };
// R25-P2-1: these example hosts are allowlisted under four different operators
const AL = ["idx-a.example", "idx-b.example", "algod-c.example", "algod-d.example"].map((host, i) => ({ host, operator: `op-${i}` }));
const TP = { ...TESTNET_PROFILE, providerAllowlist: AL };

describe("R24-P2-1 twoProviderNoConfirmProof", () => {
  it("refuses a bad provider set at construction", () => {
    const f = fakeFetch({});
    expect(() => twoProviderNoConfirmProof([A], f, { profile: TP, unsafeTestCustomFetch: true })).toThrow(IndexerOptsError);
    expect(() => twoProviderNoConfirmProof([A, { ...A, url: "https://IDX-A.example/v2" }], f, { profile: TP, unsafeTestCustomFetch: true })).toThrow(/different hosts/);
    expect(() => twoProviderNoConfirmProof([G, { ...G, url: "https://algod-d.example" }], f, { profile: TP, unsafeTestCustomFetch: true })).toThrow(/indexer/);
    expect(() => twoProviderNoConfirmProof([A, B], f, { profile: TP, unsafeTestCustomFetch: true, marginRounds: -1 })).toThrow(/non-negative/);
    expect(() => twoProviderNoConfirmProof([A, { url: "ftp://x", kind: "indexer" }], f, { profile: TP, unsafeTestCustomFetch: true })).toThrow(/http/);
  });

  it("needs both providers to agree; returns both observations", async () => {
    const ok = twoProviderNoConfirmProof([A, B], fakeFetch({ "idx-a.example": idx(1500, 404), "idx-b.example": idx(1490, 404) }), { profile: TP, unsafeTestCustomFetch: true });
    expect(await ok(row)).toEqual({
      ok: true, txId: "TX1", lastValid: 1000, marginRounds: 10,
      observations: [
        { provider: "idx-a.example", kind: "indexer", genesisHash: TN, round: 1500, status: 404, operator: "op-0" },
        { provider: "idx-b.example", kind: "indexer", genesisHash: TN, round: 1490, status: 404, operator: "op-1" },
      ],
    });
    const p = (b: Routes) => twoProviderNoConfirmProof([A, B], fakeFetch({ "idx-a.example": idx(1500, 404), "idx-b.example": b }), { profile: TP, unsafeTestCustomFetch: true })(row);
    expect(await p(idx(1500, 200))).toMatchObject({ ok: false, why: expect.stringMatching(/idx-b.example: txn found/) });
    expect(await p(idx(1005, 404))).toMatchObject({ ok: false, why: expect.stringMatching(/idx-b.example: current round 1005 is not past lastValid 1000 \+ margin 10/) });
    expect(await p(idx(1500, 404, MAINNET_PROFILE.caip2.slice(9), "mainnet-v1.0"))).toMatchObject({ ok: false, why: expect.stringMatching(/idx-b.example: indexer genesis does not match testnet/) });
    expect(await p(idx(1500, 500))).toMatchObject({ ok: false, why: expect.stringMatching(/returned 500/) });
    expect(await p({})).toMatchObject({ ok: false });
    expect(await twoProviderNoConfirmProof([A, B], fakeFetch({}), { profile: TP, unsafeTestCustomFetch: true })({ ...row, txId: null })).toMatchObject({ ok: false, why: "reservation has no txId" });
  });

  it("supports an algod second observation (genesis via /versions, pending 404, last-round)", async () => {
    const run = (g: Routes) => twoProviderNoConfirmProof([A, G], fakeFetch({ "idx-a.example": idx(1500, 404), "algod-c.example": g }), { profile: TP, unsafeTestCustomFetch: true })(row);
    expect(await run(algod(1600, 404))).toMatchObject({ ok: true, observations: [{ kind: "indexer" }, { provider: "algod-c.example", kind: "algod", round: 1600, status: 404 }] });
    expect(await run(algod(1600, 200))).toMatchObject({ ok: false, why: expect.stringMatching(/pending or recently confirmed/) });
    expect(await run(algod(1600, 404, "wrong"))).toMatchObject({ ok: false, why: expect.stringMatching(/algod genesis does not match/) });
    expect(await run(algod(1010, 404))).toMatchObject({ ok: false, why: expect.stringMatching(/not past/) });
  });
});

import { describe, expect, it } from "vitest";
import { indexerNoConfirmProof, indexerTxCheck, MAINNET_PROFILE, TESTNET_PROFILE } from "./index.js";
const IDX_TP = { ...TESTNET_PROFILE, providerAllowlist: [{ host: "idx.example", operator: "test" }] };

const TN_GENESIS = { "genesis-id": "testnet-v1.0", "genesis-hash": TESTNET_PROFILE.caip2.slice(9) };
const MN_GENESIS = { "genesis-id": "mainnet-v1.0", "genesis-hash": MAINNET_PROFILE.caip2.slice(9) };
const base = { id: "x", payer: "P", amountMicro: 1n, status: "ambiguous" as const, createdMs: 0, updatedMs: 0, lastValid: 900 };

function idx(o: { genesis: () => Response; tx?: () => Response; health?: () => Response; calls?: string[] }) {
  return (async (url: string) => {
    o.calls?.push(url);
    if (url.endsWith("/v2/blocks/0")) return o.genesis();
    if (url.endsWith("/health")) return (o.health ?? (() => new Response(JSON.stringify({ round: 2000 }))))();
    return (o.tx ?? (() => new Response(JSON.stringify({ transaction: { "confirmed-round": 5 } }))))();
  }) as unknown as typeof fetch;
}

describe("R21-P3-4 indexerTxCheck hardening", () => {
  it("200 path: a wrong-network indexer never yields settled", async () => {
    const chk = indexerTxCheck("https://idx.example", idx({ genesis: () => new Response(JSON.stringify(MN_GENESIS)) }), { profile: IDX_TP, unsafeTestCustomFetch: true });
    expect(await chk({ ...base, txId: "T" })).toBe("unknown");
    const ok = indexerTxCheck("https://idx.example", idx({ genesis: () => new Response(JSON.stringify(TN_GENESIS)) }), { profile: IDX_TP, unsafeTestCustomFetch: true });
    expect(await ok({ ...base, txId: "T" })).toBe("settled");
  });

  it("a failed genesis check is not cached; a later match is accepted, then cached", async () => {
    let n = 0;
    const calls: string[] = [];
    const f = idx({ calls, genesis: () => (++n === 1 ? new Response("", { status: 503 }) : new Response(JSON.stringify(TN_GENESIS))) });
    const chk = indexerTxCheck("https://idx.example", f, { profile: IDX_TP, unsafeTestCustomFetch: true });
    expect(await chk({ ...base, txId: "T" })).toBe("unknown");
    expect(await chk({ ...base, txId: "T" })).toBe("settled");
    expect(await chk({ ...base, txId: "T" })).toBe("settled");
    expect(calls.filter((u) => u.endsWith("/v2/blocks/0"))).toHaveLength(2);
    // a mismatch is not cached as a pass either
    let mm = true;
    const chk2 = indexerTxCheck("https://idx.example", idx({ genesis: () => new Response(JSON.stringify(mm ? MN_GENESIS : TN_GENESIS)) }), { profile: IDX_TP, unsafeTestCustomFetch: true });
    expect(await chk2({ ...base, txId: "T" })).toBe("unknown");
    mm = false;
    expect(await chk2({ ...base, txId: "T" })).toBe("settled");
  });

  it("null / malformed bodies are unknown, never settled or released", async () => {
    const nullTx = indexerTxCheck("https://idx.example", idx({ genesis: () => new Response(JSON.stringify(TN_GENESIS)), tx: () => new Response("null") }), { profile: IDX_TP, unsafeTestCustomFetch: true });
    expect(await nullTx({ ...base, txId: "T" })).toBe("unknown");
    const strRound = indexerTxCheck("https://idx.example", idx({ genesis: () => new Response(JSON.stringify(TN_GENESIS)), tx: () => new Response(JSON.stringify({ transaction: { "confirmed-round": "5" } })) }), { profile: IDX_TP, unsafeTestCustomFetch: true });
    expect(await strRound({ ...base, txId: "T" })).toBe("unknown");
    const nullGen = indexerTxCheck("https://idx.example", idx({ genesis: () => new Response("null") }), { profile: IDX_TP, unsafeTestCustomFetch: true });
    expect(await nullGen({ ...base, txId: "T" })).toBe("unknown");
    const nf = () => new Response("{}", { status: 404 });
    const nullHealth = indexerTxCheck("https://idx.example", idx({ genesis: () => new Response(JSON.stringify(TN_GENESIS)), tx: nf, health: () => new Response("null") }), { profile: IDX_TP, unsafeTestCustomFetch: true });
    expect(await nullHealth({ ...base, txId: "T" })).toBe("unknown");
    const strHealth = indexerTxCheck("https://idx.example", idx({ genesis: () => new Response(JSON.stringify(TN_GENESIS)), tx: nf, health: () => new Response(JSON.stringify({ round: "99999" })) }), { profile: IDX_TP, unsafeTestCustomFetch: true });
    expect(await strHealth({ ...base, txId: "T" })).toBe("unknown");
    const p = indexerNoConfirmProof("https://idx.example", idx({ genesis: () => new Response("null"), tx: nf }), { profile: TESTNET_PROFILE });
    expect(await p({ ...base, txId: "T" })).toMatchObject({ ok: false, why: expect.stringMatching(/genesis/) });
  });
});

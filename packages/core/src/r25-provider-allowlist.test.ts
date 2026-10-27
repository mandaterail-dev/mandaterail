/** R25-P2-1: provider allowlist with operator ids (network profile), loopback / localhost / .invalid refused. */
import { describe, expect, it } from "vitest";
import { isForbiddenProviderHost, MAINNET_PROFILE, TESTNET_PROFILE } from "./network.js";
import { twoProviderNoConfirmProof, type SpendReservation } from "./spend-caps.js";

const TN = TESTNET_PROFILE.caip2.slice(9);
const f = (async (input: string | URL) => {
  const u = new URL(String(input));
  if (u.pathname === "/v2/blocks/0") return new Response(JSON.stringify({ "genesis-id": "testnet-v1.0", "genesis-hash": TN }), { status: 200 });
  if (u.pathname === "/health") return new Response(JSON.stringify({ round: 1500 }), { status: 200 });
  return new Response("{}", { status: 404 });
}) as typeof fetch;
const row = { id: "r", payer: "P", amountMicro: 1n, status: "ambiguous", createdMs: 0, updatedMs: 0, txId: "TX1", lastValid: 1000 } as SpendReservation;
const idx = (h: string) => ({ url: `https://${h}`, kind: "indexer" as const });

describe("R25-P2-1 provider allowlist", () => {
  it("profiles carry an allowlist; Nodely/algonode is ONE operator; MainNet adds GetBlock + Blockdaemon", () => {
    for (const p of [TESTNET_PROFILE, MAINNET_PROFILE]) {
      expect(p.providerAllowlist.length).toBeGreaterThan(0);
      expect(new Set(p.providerAllowlist.map((e) => e.operator))).toEqual(new Set(p === MAINNET_PROFILE ? ["nodely", "getblock", "blockdaemon", "drpc"] : ["nodely"]));
      for (const e of p.providerAllowlist) expect(isForbiddenProviderHost(e.host)).toBe(false);
    }
  });

  it("forbidden hosts", () => {
    for (const h of ["localhost", "a.localhost", "127.0.0.1", "127.0.0.1:8080", "[::1]", "::1", "10.0.0.1", "x.invalid", "invalid", "LOCALHOST."]) expect(isForbiddenProviderHost(h), h).toBe(true);
    for (const h of ["testnet-idx.algonode.cloud", "node.example.com:8443"]) expect(isForbiddenProviderHost(h), h).toBe(false);
  });

  it("the run-25 bypass pairs are refused before any fetch", () => {
    const P = { profile: TESTNET_PROFILE };
    expect(() => twoProviderNoConfirmProof([{ url: "http://127.0.0.1:1", kind: "indexer" }, { url: "http://localhost:1", kind: "indexer" }], f, P)).toThrow(/loopback/);
    expect(() => twoProviderNoConfirmProof([idx("testnet-idx.algonode.cloud"), idx("testnet-idx.algonode.cloud:443")], f, P)).toThrow(/different hosts/);
    expect(() => twoProviderNoConfirmProof([idx("x.invalid"), idx("y.invalid")], f, P)).toThrow(/\.invalid/);
    expect(() => twoProviderNoConfirmProof([idx("testnet-idx.algonode.cloud"), idx("unknown.example.com")], f, P)).toThrow(/not on the testnet provider allowlist/);
    // algonode + nodely: different hosts, same operator
    expect(() => twoProviderNoConfirmProof([idx("testnet-idx.algonode.cloud"), { url: "https://testnet-api.4160.nodely.dev", kind: "algod" }], f, P)).toThrow(/different operators \(both are nodely\)/);
    // a TestNet host is not on the MainNet list
    expect(() => twoProviderNoConfirmProof([idx("testnet-idx.algonode.cloud"), idx("mainnet-idx.algonode.cloud")], f, { profile: MAINNET_PROFILE, unsafeTestCustomFetch: true })).toThrow(/not on the mainnet provider allowlist/);
  });

  it("two allowlisted operators pass and each observation records its operator", async () => {
    const allowlist = [{ host: "testnet-idx.algonode.cloud", operator: "nodely" }, { host: "idx.own-node.example.com", operator: "own-node" }];
    const r = await twoProviderNoConfirmProof([idx("testnet-idx.algonode.cloud"), idx("idx.own-node.example.com")], f, { profile: { ...TESTNET_PROFILE, providerAllowlist: allowlist }, unsafeTestCustomFetch: true })(row);
    expect(r).toMatchObject({ ok: true, observations: [{ provider: "testnet-idx.algonode.cloud", operator: "nodely" }, { provider: "idx.own-node.example.com", operator: "own-node" }] });
  });
});

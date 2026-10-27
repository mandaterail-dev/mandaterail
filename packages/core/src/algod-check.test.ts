import { describe, expect, it } from "vitest";
import { AlgodProfileError, algodCheckRequired, MAINNET_PROFILE, TESTNET_PROFILE, verifyAlgodMatchesProfile } from "./index.js";

function fakeAlgod(genesis: string, decimals: number | undefined, seen: string[] = []) {
  return (async (url: string, init?: RequestInit) => {
    seen.push(`${url} ${JSON.stringify(init?.headers ?? {})}`);
    if (url.endsWith("/versions")) return new Response(JSON.stringify({ genesis_hash_b64: genesis }), { status: 200 });
    if (url.includes("/v2/assets/")) return new Response(JSON.stringify({ params: decimals === undefined ? {} : { decimals } }), { status: 200 });
    return new Response("", { status: 404 });
  }) as unknown as typeof fetch;
}
const MAIN = "wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=";
const TEST = "SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=";

describe("T5-P3 algod startup check", () => {
  it("accepts matching genesis + 6 decimals; queries the profile ASA", async () => {
    const seen: string[] = [];
    await expect(verifyAlgodMatchesProfile(MAINNET_PROFILE, { algodUrl: "https://algod.example/", token: "t0k", fetchImpl: fakeAlgod(MAIN, 6, seen) })).resolves.toEqual({ genesisHash: MAIN, decimals: 6 });
    expect(seen[1]).toContain("/v2/assets/31566704");
    expect(seen[0]).toContain("X-Algo-API-Token");
    await expect(verifyAlgodMatchesProfile(TESTNET_PROFILE, { fetchImpl: fakeAlgod(TEST, 6) })).resolves.toBeTruthy();
  });
  it("refuses a TestNet algod for the MainNet profile (and vice versa)", async () => {
    await expect(verifyAlgodMatchesProfile(MAINNET_PROFILE, { fetchImpl: fakeAlgod(TEST, 6) })).rejects.toThrow(AlgodProfileError);
    await expect(verifyAlgodMatchesProfile(TESTNET_PROFILE, { fetchImpl: fakeAlgod(MAIN, 6) })).rejects.toThrow(/genesis/);
  });
  it("refuses decimals other than 6", async () => {
    await expect(verifyAlgodMatchesProfile(MAINNET_PROFILE, { fetchImpl: fakeAlgod(MAIN, 2) })).rejects.toThrow(/decimals 2/);
    await expect(verifyAlgodMatchesProfile(MAINNET_PROFILE, { fetchImpl: fakeAlgod(MAIN, undefined) })).rejects.toThrow(AlgodProfileError);
  });
  it("unreachable / HTTP errors refuse without echoing the URL or token", async () => {
    const boom = (async () => { throw new Error("connect ECONNREFUSED https://user:secret@algod.example"); }) as unknown as typeof fetch;
    const err = (await verifyAlgodMatchesProfile(MAINNET_PROFILE, { algodUrl: "https://user:secret@algod.example", token: "secret", fetchImpl: boom }).catch((e) => e)) as Error;
    expect(err).toBeInstanceOf(AlgodProfileError);
    expect(err.message).not.toContain("secret");
    const e500 = (async () => new Response("", { status: 500 })) as unknown as typeof fetch;
    await expect(verifyAlgodMatchesProfile(MAINNET_PROFILE, { fetchImpl: e500 })).rejects.toThrow(/HTTP 500/);
  });
  it("required on MainNet; opt-in on TestNet", () => {
    expect(algodCheckRequired(MAINNET_PROFILE, {})).toBe(true);
    expect(algodCheckRequired(TESTNET_PROFILE, {})).toBe(false);
    expect(algodCheckRequired(TESTNET_PROFILE, { ALGOD_CHECK: "1" })).toBe(true);
  });
});

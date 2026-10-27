/** R54 + Blockdaemon (operator 3): auth headers per provider host, path-token detection. */
import { describe, expect, it, vi } from "vitest";
import { MAINNET_PROFILE, providerAuthHeaders, requireProviderKey, urlHasPathToken, isTokenLikePathSegment, verifyAlgodMatchesProfile } from "./index.js";

const FAKE = "fake-key-not-a-secret-0000";
describe("R54 providers", () => {
  it("Blockdaemon gets X-API-Key; algod / indexer hosts keep their token headers; no token = no header", () => {
    expect(providerAuthHeaders("https://svc.blockdaemon.com/algorand/mainnet/native", "algod", FAKE)).toEqual({ "X-API-Key": FAKE });
    expect(providerAuthHeaders("https://SVC.blockdaemon.com./algorand/mainnet/native/indexer", "indexer", FAKE)).toEqual({ "X-API-Key": FAKE });
    expect(providerAuthHeaders("https://mainnet-api.4160.nodely.dev", "algod", FAKE)).toEqual({ "X-Algo-API-Token": FAKE });
    expect(providerAuthHeaders("https://mainnet-idx.4160.nodely.dev", "indexer", FAKE)).toEqual({ "X-Indexer-API-Token": FAKE });
    expect(providerAuthHeaders("https://svc.blockdaemon.com/x", "algod", undefined)).toEqual({});
  });
  it("Blockdaemon is MainNet operator 3, distinct from nodely and getblock", () => {
    const e = MAINNET_PROFILE.providerAllowlist.find((x) => x.host === "svc.blockdaemon.com");
    expect(e?.operator).toBe("blockdaemon");
  });
  it("path tokens are detected (GetBlock host or a token-like segment); plain paths are not", () => {
    expect(isTokenLikePathSegment("0123456789abcdef0123456789abcdef")).toBe(true);
    expect(isTokenLikePathSegment("health")).toBe(false);
    expect(isTokenLikePathSegment("mainnet-v1-indexer-health")).toBe(false);
    expect(urlHasPathToken("https://shared.eu-central-1.getblock.io/abc/")).toBe(true);
    expect(urlHasPathToken("https://h.example/0123456789abcdef0123456789abcdef/health")).toBe(true);
    expect(urlHasPathToken("https://svc.blockdaemon.com/algorand/mainnet/native/indexer")).toBe(false);
    expect(urlHasPathToken("https://mr-api.example/health")).toBe(false);
  });
  it("the startup algod check sends X-API-Key to Blockdaemon", async () => {
    const seen: Array<Record<string, string>> = [];
    const f = vi.fn(async (_u: string, init?: RequestInit) => {
      seen.push(init?.headers as Record<string, string>);
      const u = String(_u);
      if (u.endsWith("/versions")) return new Response(JSON.stringify({ genesis_hash_b64: MAINNET_PROFILE.caip2.slice(9) }));
      return new Response(JSON.stringify({ params: { decimals: 6 } }));
    });
    await verifyAlgodMatchesProfile(MAINNET_PROFILE, { algodUrl: "https://svc.blockdaemon.com/algorand/mainnet/native", token: FAKE, fetchImpl: f as unknown as typeof fetch });
    expect(seen.every((h) => h["X-API-Key"] === FAKE && !("X-Algo-API-Token" in h))).toBe(true);
  });
  it("run 55: a Blockdaemon URL without its key is refused explicitly (env var named, no value)", () => {
    expect(() => requireProviderKey("https://svc.blockdaemon.com/algorand/mainnet/native/indexer", undefined, "PROOF2_TOKEN")).toThrow(/PROOF2_TOKEN is required for svc\.blockdaemon\.com/);
    expect(() => requireProviderKey("https://svc.blockdaemon.com/algorand/mainnet/native/indexer", " ", "PROOF2_TOKEN")).toThrow();
    expect(() => requireProviderKey("https://svc.blockdaemon.com/algorand/mainnet/native/indexer", FAKE, "PROOF2_TOKEN")).not.toThrow();
    expect(() => requireProviderKey("https://mainnet-api.4160.nodely.dev", undefined, "PROOF2_TOKEN")).not.toThrow();
    expect(() => requireProviderKey(undefined, undefined, "PROOF2_TOKEN")).not.toThrow();
  });
});

/** R54-P3-4 + Blockdaemon: X-API-Key from an env var NAME, provider validation, 0600 for path-token configs. */
import { describe, expect, it } from "vitest";
import { assertConfigFileModeForProviders, ConfigError, validatePinnedProvider, type PinnedProvider } from "../src/config.js";
import { HttpProbe, type FetchFn } from "../src/providers.js";

const BD: PinnedProvider = { host: "svc.blockdaemon.com", operator: "blockdaemon", kind: "indexer", baseUrl: "https://svc.blockdaemon.com/algorand/mainnet/native/indexer", apiKeyEnv: "BLOCKDAEMON_API_KEY" };
describe("R54 signer/verifier providers", () => {
  it("HttpProbe sends X-API-Key from the named env var; refuses when it is unset; others send no auth header", async () => {
    const seen: Array<{ url: string; h?: Record<string, string> }> = [];
    const f: FetchFn = async (url, init) => { seen.push({ url, h: init?.headers }); return { status: 500, json: async () => ({}) }; };
    await new HttpProbe(BD, f, 1000, { BLOCKDAEMON_API_KEY: "fake-key" }).probe(["A"], 1, 2);
    expect(seen[0]!.url).toBe("https://svc.blockdaemon.com/algorand/mainnet/native/indexer/health");
    expect(seen[0]!.h).toEqual({ "X-API-Key": "fake-key" });
    expect(seen[0]!.url).not.toContain("fake-key");
    expect(() => new HttpProbe(BD, f, 1000, {})).toThrow(/BLOCKDAEMON_API_KEY is not set/);
    seen.length = 0;
    await new HttpProbe({ host: "mainnet-idx.4160.nodely.dev", operator: "nodely", kind: "indexer", baseUrl: "https://mainnet-idx.4160.nodely.dev" }, f, 1000, {}).probe(["A"], 1, 2);
    expect(seen[0]!.h).toEqual({});
  });
  it("validatePinnedProvider: Blockdaemon needs apiKeyEnv (a NAME); no query/credentials in baseUrl", () => {
    expect(() => validatePinnedProvider(BD)).not.toThrow();
    expect(() => validatePinnedProvider({ ...BD, apiKeyEnv: undefined })).toThrow(ConfigError);
    expect(() => validatePinnedProvider({ ...BD, apiKeyEnv: "bd-key=abc" })).toThrow(/env var NAME/);
    expect(() => validatePinnedProvider({ ...BD, baseUrl: BD.baseUrl + "?apiKey=x" })).toThrow(/no credentials, query/);
    expect(() => validatePinnedProvider({ host: "mainnet-idx.4160.nodely.dev", operator: "nodely", kind: "indexer", baseUrl: "https://mainnet-idx.4160.nodely.dev", apiKeyEnv: "X_KEY" })).toThrow(/only for X-API-Key/);
  });
  it("P3-4: a config holding a path-token baseUrl must be 0600; others are not checked", () => {
    const gb = [{ baseUrl: "https://shared.eu-central-1.getblock.io/0123456789abcdef0123456789abcdef/" }];
    expect(() => assertConfigFileModeForProviders("/x/c.json", gb, () => ({ mode: 0o100644 }))).toThrow(/chmod 0600/);
    expect(() => assertConfigFileModeForProviders("/x/c.json", gb, () => ({ mode: 0o100600 }))).not.toThrow();
    expect(() => assertConfigFileModeForProviders("/x/c.json", [{ baseUrl: BD.baseUrl }], () => ({ mode: 0o100644 }))).not.toThrow();
  });
});

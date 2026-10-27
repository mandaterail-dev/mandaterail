import { describe, expect, it } from "vitest";
import {
  ALGORAND_MAINNET_CAIP2,
  ALGORAND_TESTNET_CAIP2,
  networkProfile,
  NetworkProfileError,
  USDC_MAINNET_ASA,
  USDC_TESTNET_ASA,
} from "./index.js";

describe("T5 networkProfile()", () => {
  it("defaults to TestNet USDC (Phase-1 behaviour)", () => {
    const p = networkProfile({});
    expect(p).toMatchObject({ name: "testnet", caip2: ALGORAND_TESTNET_CAIP2, usdcAsaId: "10458941", isMainnet: false });
    expect(networkProfile({ NETWORK: ALGORAND_TESTNET_CAIP2 }).usdcAsaId).toBe(USDC_TESTNET_ASA);
    expect(networkProfile({ NETWORK: "testnet" }).name).toBe("testnet");
  });
  it("MainNet -> USDC 31566704 + mainnet explorer", () => {
    for (const NETWORK of [ALGORAND_MAINNET_CAIP2, "mainnet", "MainNet"]) {
      const p = networkProfile({ NETWORK });
      expect(p.usdcAsaId).toBe("31566704");
      expect(p.caip2).toBe(ALGORAND_MAINNET_CAIP2);
      expect(p.explorerTxBase).toContain("/mainnet/");
      expect(p.isMainnet).toBe(true);
    }
    expect(networkProfile({ NETWORK: "mainnet", ALLOW_MAINNET: "1", USDC_ASA_ID: USDC_MAINNET_ASA }).usdcAsaId).toBe(USDC_MAINNET_ASA);
  });
  it("refuses the TestNet ASA (or any other) on MainNet", () => {
    expect(() => networkProfile({ NETWORK: "mainnet", USDC_ASA_ID: "10458941" })).toThrow(NetworkProfileError);
  });
  it("refuses the MainNet ASA on TestNet; allows a lab override", () => {
    expect(() => networkProfile({ NETWORK: "testnet", USDC_ASA_ID: USDC_MAINNET_ASA })).toThrow(NetworkProfileError);
    expect(networkProfile({ USDC_ASA_ID: "12345" }).usdcAsaId).toBe("12345");
  });
  it("fails closed on ambiguous or unknown networks", () => {
    expect(() => networkProfile({ ALLOW_MAINNET: "true" })).toThrow(/ambiguous/);
    expect(() => networkProfile({ NETWORK: "testnet", ALLOW_MAINNET: "1" })).toThrow(NetworkProfileError);
    expect(() => networkProfile({ NETWORK: "betanet" })).toThrow(/unknown/);
    expect(() => networkProfile({ NETWORK: "my-mainnet-fork" })).toThrow(NetworkProfileError);
    expect(() => networkProfile({ NETWORK: "testnet-ish" })).toThrow(NetworkProfileError);
  });
});

import { afterEach, describe, expect, it } from "vitest";
import {
  ALGORAND_MAINNET_CAIP2,
  validateMerchantApiKeyPrefix,
  resolveApiKeyNetworkMode,
  isNetworkMainnetExplicit,
} from "./api-key.js";
import { ALGORAND_TESTNET_CAIP2 } from "./insecure-dev.js";

const KEYS = ["NETWORK", "ALLOW_MAINNET"] as const;
const saved: Record<string, string | undefined> = {};

afterEach(() => {
  for (const k of KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
    delete saved[k];
  }
});

function setEnv(k: (typeof KEYS)[number], v: string | undefined) {
  if (!(k in saved)) saved[k] = process.env[k];
  if (v === undefined) delete process.env[k];
  else process.env[k] = v;
}

describe("merchant API key prefix validation", () => {
  it("defaults to testnet mode and accepts mr_test_", () => {
    setEnv("NETWORK", undefined);
    setEnv("ALLOW_MAINNET", undefined);
    expect(resolveApiKeyNetworkMode()).toBe("testnet");
    const ok = validateMerchantApiKeyPrefix("mr_test_demo_abc");
    expect(ok.ok).toBe(true);
  });

  it("rejects mr_live_ on TestNet", () => {
    setEnv("NETWORK", ALGORAND_TESTNET_CAIP2);
    setEnv("ALLOW_MAINNET", undefined);
    const r = validateMerchantApiKeyPrefix("mr_live_prod_abc");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toBe("api_key_network_mismatch");
  });

  it("rejects mr_test_ when MainNet explicitly enabled", () => {
    setEnv("NETWORK", ALGORAND_MAINNET_CAIP2);
    setEnv("ALLOW_MAINNET", "1");
    expect(isNetworkMainnetExplicit()).toBe(true);
    const r = validateMerchantApiKeyPrefix("mr_test_lab");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toBe("api_key_network_mismatch");
  });

  it("accepts mr_live_ only when MainNet explicitly enabled", () => {
    setEnv("NETWORK", ALGORAND_MAINNET_CAIP2);
    setEnv("ALLOW_MAINNET", "1");
    const r = validateMerchantApiKeyPrefix("mr_live_prod_xyz");
    expect(r.ok).toBe(true);
  });

  it("does not treat MainNet NETWORK alone as enabled without ALLOW_MAINNET", () => {
    setEnv("NETWORK", ALGORAND_MAINNET_CAIP2);
    setEnv("ALLOW_MAINNET", undefined);
    expect(isNetworkMainnetExplicit()).toBe(false);
    expect(resolveApiKeyNetworkMode()).toBe("testnet");
    const r = validateMerchantApiKeyPrefix("mr_live_prod_xyz");
    expect(r.ok).toBe(false);
  });

  it("rejects unknown prefixes", () => {
    setEnv("NETWORK", ALGORAND_TESTNET_CAIP2);
    const r = validateMerchantApiKeyPrefix("sk_live_other");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toBe("invalid_api_key_prefix");
  });
});

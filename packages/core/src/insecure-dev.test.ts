import { afterEach, describe, expect, it } from "vitest";
import {
  authorizeOperator,
  checkInsecureDev,
  checkOperatorGate,
  parseChallengeTtlMs,
  parseChallengeRateLimits,
  parseTrustedProxyHops,
  isLoopbackHost,
  isTrustedLocalRequest,
  normalizeClientKey,
  maxLiveChallenges,
  CHALLENGE_STORE_MAX_ENTRIES,
  MAX_CHALLENGE_TTL_MS,
  MAX_CHALLENGE_RATE_GLOBAL,
  isLoopbackAddress,
  isNetworkTestnet,
  listEnabledInsecureFlags,
  ALGORAND_TESTNET_CAIP2,
  ALGORAND_MAINNET_CAIP2,
} from "./insecure-dev.js";
import algosdk from "algosdk";

const ADDR = algosdk.generateAccount().addr.toString();

const KEYS = [
  "ALLOW_INSECURE_DEV",
  "ALLOW_MAINNET",
  "AC2_BRIDGE_AUTO_LOCAL",
  "DEV_ALLOW_UNSIGNED",
  "AC2_OPERATOR_TOKEN",
  "NETWORK",
  "OPERATOR_ATTESTATION_MODE",
  "OPERATOR_ALLOWLIST",
  "OPERATOR_SIGNDATA_DOMAIN",
  "OPERATOR_CHALLENGE_TTL_MS",
  "AC2_BRIDGE_HOST",
  "OPERATOR_CHALLENGE_RATE_PER_IP",
  "OPERATOR_CHALLENGE_RATE_GLOBAL",
  "AC2_BRIDGE_TRUSTED_PROXY_HOPS",
] as const;

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

describe("insecure-dev helpers", () => {
  it("detects loopback addresses", () => {
    expect(isLoopbackAddress("127.0.0.1")).toBe(true);
    expect(isLoopbackAddress("::1")).toBe(true);
    expect(isLoopbackAddress("::ffff:127.0.0.1")).toBe(true);
    expect(isLoopbackAddress("10.0.0.1")).toBe(false);
    expect(isLoopbackAddress(undefined)).toBe(false);
  });

  it("detects TestNet NETWORK", () => {
    expect(isNetworkTestnet(ALGORAND_TESTNET_CAIP2)).toBe(true);
    expect(isNetworkTestnet("algorand:testnet")).toBe(true);
    expect(isNetworkTestnet("algorand:mainnet")).toBe(false);
    expect(isNetworkTestnet("")).toBe(false);
  });

  it("lists insecure flags including ALLOW_INSECURE_DEV", () => {
    setEnv("AC2_BRIDGE_AUTO_LOCAL", "true");
    setEnv("DEV_ALLOW_UNSIGNED", "1");
    setEnv("ALLOW_INSECURE_DEV", "1");
    expect(listEnabledInsecureFlags()).toEqual([
      "AC2_BRIDGE_AUTO_LOCAL",
      "DEV_ALLOW_UNSIGNED",
      "ALLOW_INSECURE_DEV",
    ]);
  });

  it("requires operator token when set", () => {
    setEnv("AC2_OPERATOR_TOKEN", "secret-token");
    expect(
      authorizeOperator({ headerToken: "secret-token", remoteAddress: "10.0.0.2" })
        .ok,
    ).toBe(true);
    expect(
      authorizeOperator({ headerToken: "wrong", remoteAddress: "127.0.0.1" }).ok,
    ).toBe(false);
  });

  it("allows TestNet+loopback+ALLOW_INSECURE_DEV when token unset", () => {
    setEnv("AC2_OPERATOR_TOKEN", undefined);
    setEnv("ALLOW_INSECURE_DEV", "1");
    setEnv("NETWORK", ALGORAND_TESTNET_CAIP2);
    setEnv("ALLOW_MAINNET", undefined);
    expect(
      authorizeOperator({ headerToken: undefined, remoteAddress: "127.0.0.1" })
        .ok,
    ).toBe(true);
  });

  it("denies loopback+ALLOW_INSECURE_DEV when NETWORK is MainNet", () => {
    setEnv("AC2_OPERATOR_TOKEN", undefined);
    setEnv("ALLOW_INSECURE_DEV", "1");
    setEnv("NETWORK", ALGORAND_MAINNET_CAIP2);
    setEnv("ALLOW_MAINNET", undefined);
    expect(
      authorizeOperator({ headerToken: undefined, remoteAddress: "127.0.0.1" })
        .ok,
    ).toBe(false);
  });

  it("denies loopback+ALLOW_INSECURE_DEV when ALLOW_MAINNET=1 even on TestNet", () => {
    setEnv("AC2_OPERATOR_TOKEN", undefined);
    setEnv("ALLOW_INSECURE_DEV", "1");
    setEnv("NETWORK", ALGORAND_TESTNET_CAIP2);
    setEnv("ALLOW_MAINNET", "1");
    expect(
      authorizeOperator({ headerToken: undefined, remoteAddress: "127.0.0.1" })
        .ok,
    ).toBe(false);
  });

  it("denies loopback when ALLOW_INSECURE_DEV unset or remote is non-loopback", () => {
    setEnv("AC2_OPERATOR_TOKEN", undefined);
    setEnv("NETWORK", ALGORAND_TESTNET_CAIP2);
    setEnv("ALLOW_INSECURE_DEV", undefined);
    expect(
      authorizeOperator({ headerToken: undefined, remoteAddress: "127.0.0.1" })
        .ok,
    ).toBe(false);
    setEnv("ALLOW_INSECURE_DEV", "1");
    expect(
      authorizeOperator({ headerToken: undefined, remoteAddress: "8.8.8.8" }).ok,
    ).toBe(false);
  });

  it("checkInsecureDev refuses ALLOW_INSECURE_DEV without TestNet NETWORK", () => {
    setEnv("ALLOW_INSECURE_DEV", "1");
    setEnv("NETWORK", ALGORAND_MAINNET_CAIP2);
    const r = checkInsecureDev();
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/TestNet/);
  });

  it("checkInsecureDev accepts ALLOW_INSECURE_DEV + TestNet", () => {
    setEnv("ALLOW_INSECURE_DEV", "1");
    setEnv("NETWORK", ALGORAND_TESTNET_CAIP2);
    const r = checkInsecureDev();
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.warned).toBe(true);
  });

  it("checkInsecureDev refuses AUTO_LOCAL without ALLOW_INSECURE_DEV", () => {
    setEnv("AC2_BRIDGE_AUTO_LOCAL", "1");
    setEnv("ALLOW_INSECURE_DEV", undefined);
    setEnv("NETWORK", ALGORAND_TESTNET_CAIP2);
    const r = checkInsecureDev();
    expect(r.ok).toBe(false);
  });

  it("checkOperatorGate refuses MainNet NETWORK without OPERATOR_ALLOWLIST (signed-challenge default)", () => {
    setEnv("NETWORK", ALGORAND_MAINNET_CAIP2);
    setEnv("ALLOW_MAINNET", undefined);
    setEnv("OPERATOR_ATTESTATION_MODE", undefined);
    setEnv("OPERATOR_ALLOWLIST", undefined);
    const r = checkOperatorGate();
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/OPERATOR_ALLOWLIST/);
  });

  it("checkOperatorGate refuses token-lab on ALLOW_MAINNET=1 even with token + allowlist", () => {
    setEnv("NETWORK", ALGORAND_TESTNET_CAIP2);
    setEnv("ALLOW_MAINNET", "1");
    setEnv("AC2_OPERATOR_TOKEN", "secret");
    setEnv("OPERATOR_ATTESTATION_MODE", "token-lab");
    setEnv("OPERATOR_ALLOWLIST", ADDR);
    const r = checkOperatorGate();
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/token-lab/);
  });

  it("checkOperatorGate ok when MainNet + signed-challenge + allowlist", () => {
    setEnv("NETWORK", ALGORAND_MAINNET_CAIP2);
    setEnv("ALLOW_MAINNET", "1");
    setEnv("OPERATOR_ATTESTATION_MODE", "signed-challenge");
    setEnv("OPERATOR_ALLOWLIST", ADDR);
    setEnv("OPERATOR_SIGNDATA_DOMAIN", "mandaterail.pages.dev");
    expect(checkOperatorGate().ok).toBe(true);
  });

  it("P1-A: checkOperatorGate refuses MainNet signed-challenge without OPERATOR_SIGNDATA_DOMAIN", () => {
    setEnv("NETWORK", ALGORAND_MAINNET_CAIP2);
    setEnv("ALLOW_MAINNET", "1");
    setEnv("OPERATOR_ATTESTATION_MODE", "signed-challenge");
    setEnv("OPERATOR_ALLOWLIST", ADDR);
    setEnv("OPERATOR_SIGNDATA_DOMAIN", undefined);
    const r = checkOperatorGate();
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/OPERATOR_SIGNDATA_DOMAIN/);
    setEnv("OPERATOR_SIGNDATA_DOMAIN", "   ");
    expect(checkOperatorGate().ok).toBe(false);
  });

  it("OA-P2-Q: checkOperatorGate requires OPERATOR_SIGNDATA_DOMAIN for every signed-challenge deployment", () => {
    setEnv("NETWORK", ALGORAND_TESTNET_CAIP2);
    setEnv("ALLOW_MAINNET", undefined);
    setEnv("OPERATOR_ATTESTATION_MODE", "signed-challenge");
    setEnv("OPERATOR_ALLOWLIST", ADDR);
    setEnv("OPERATOR_SIGNDATA_DOMAIN", undefined);
    for (const bind of ["127.0.0.1", "localhost", "::1", "0.0.0.0", "::"]) {
      const r = checkOperatorGate({ bindHost: bind });
      expect(r.ok, bind).toBe(false);
      if (!r.ok) expect(r.reason).toMatch(/OPERATOR_SIGNDATA_DOMAIN/);
    }
    setEnv("OPERATOR_SIGNDATA_DOMAIN", "mandaterail.pages.dev");
    expect(checkOperatorGate({ bindHost: "127.0.0.1" }).ok).toBe(true);
    expect(checkOperatorGate({ bindHost: "0.0.0.0" }).ok).toBe(true);
  });

  it("P2-B: checkOperatorGate refuses invalid OPERATOR_CHALLENGE_TTL_MS", () => {
    setEnv("NETWORK", ALGORAND_TESTNET_CAIP2);
    setEnv("ALLOW_MAINNET", undefined);
    setEnv("OPERATOR_ATTESTATION_MODE", "signed-challenge");
    setEnv("OPERATOR_ALLOWLIST", ADDR);
    setEnv("AC2_BRIDGE_HOST", "127.0.0.1");
    setEnv("OPERATOR_SIGNDATA_DOMAIN", "mandaterail.pages.dev");
    for (const bad of ["NaN", "Infinity", "abc", "-5", "9999", "600001", "1e5", "120000.5"]) {
      setEnv("OPERATOR_CHALLENGE_TTL_MS", bad);
      expect(checkOperatorGate().ok, bad).toBe(false);
    }
    setEnv("OPERATOR_CHALLENGE_TTL_MS", "60000");
    expect(checkOperatorGate().ok).toBe(true);
  });

  it("P2-B: parseChallengeTtlMs bounds", () => {
    expect(parseChallengeTtlMs(undefined)).toBe(120_000);
    expect(parseChallengeTtlMs("")).toBe(120_000);
    expect(parseChallengeTtlMs("10000")).toBe(10_000);
    expect(parseChallengeTtlMs("600000")).toBe(600_000);
    expect(parseChallengeTtlMs("9999")).toBeNull();
    expect(parseChallengeTtlMs("600001")).toBeNull();
    expect(parseChallengeTtlMs("Infinity")).toBeNull();
    expect(parseChallengeTtlMs("NaN")).toBeNull();
  });

  it("checkOperatorGate refuses unknown mode", () => {
    setEnv("NETWORK", ALGORAND_TESTNET_CAIP2);
    setEnv("ALLOW_MAINNET", undefined);
    setEnv("OPERATOR_ATTESTATION_MODE", "yolo");
    expect(checkOperatorGate().ok).toBe(false);
  });

  it("authorizeOperator refuses token on MainNet profile (token-lab refused)", () => {
    setEnv("NETWORK", ALGORAND_MAINNET_CAIP2);
    setEnv("AC2_OPERATOR_TOKEN", "secret");
    const r = authorizeOperator({ headerToken: "secret", remoteAddress: "127.0.0.1" });
    expect(r.ok).toBe(false);
  });

  it("checkOperatorGate ok on TestNet without token", () => {
    setEnv("NETWORK", ALGORAND_TESTNET_CAIP2);
    setEnv("ALLOW_MAINNET", undefined);
    setEnv("AC2_OPERATOR_TOKEN", undefined);
    setEnv("OPERATOR_ATTESTATION_MODE", undefined);
    expect(checkOperatorGate().ok).toBe(true);
  });

  it("OA-P2-H: isLoopbackHost is strict", () => {
    for (const ok of ["127.0.0.1", "127.255.255.254", "localhost", "LOCALHOST", "::1", "[::1]", "::ffff:127.0.0.1"])
      expect(isLoopbackHost(ok), ok).toBe(true);
    for (const bad of ["127.example.com", "127.0.0.1.nip.io", "127.0.0.256", "127.1", "0.0.0.0", "::", "::ffff:10.0.0.1", "::ffff:127.evil.com", "localhost.evil.com", "", undefined])
      expect(isLoopbackHost(bad as string), String(bad)).toBe(false);
  });

  it("OA-P2-H: checkOperatorGate treats 127.example.com as non-loopback", () => {
    setEnv("NETWORK", ALGORAND_TESTNET_CAIP2);
    setEnv("ALLOW_MAINNET", undefined);
    setEnv("OPERATOR_ATTESTATION_MODE", "signed-challenge");
    setEnv("OPERATOR_ALLOWLIST", ADDR);
    // Domain is now always required (OA-P2-Q); test the loopback helper directly.
    setEnv("OPERATOR_SIGNDATA_DOMAIN", "mandaterail.pages.dev");
    expect(isLoopbackHost("127.example.com")).toBe(false);
    expect(isLoopbackHost("127.0.0.2")).toBe(true);
    expect(checkOperatorGate({ bindHost: "127.example.com" }).ok).toBe(true);
    setEnv("OPERATOR_SIGNDATA_DOMAIN", undefined);
    expect(checkOperatorGate({ bindHost: "127.0.0.2" }).ok).toBe(false);
  });

  it("OA-P2-G: rate limits are clamped and gate refuses out-of-range", () => {
    expect(parseChallengeRateLimits({})).toEqual({ perIp: 30, global: 600 });
    expect(parseChallengeRateLimits({ OPERATOR_CHALLENGE_RATE_GLOBAL: "801" })).toBeNull();
    expect(parseChallengeRateLimits({ OPERATOR_CHALLENGE_RATE_PER_IP: "121" })).toBeNull();
    expect(parseChallengeRateLimits({ OPERATOR_CHALLENGE_RATE_PER_IP: "0" })).toBeNull();
    expect(parseChallengeRateLimits({ OPERATOR_CHALLENGE_RATE_PER_IP: "50", OPERATOR_CHALLENGE_RATE_GLOBAL: "40" })).toBeNull();
    expect(parseTrustedProxyHops(undefined)).toBe(0);
    expect(parseTrustedProxyHops("6")).toBeNull();
    setEnv("NETWORK", ALGORAND_TESTNET_CAIP2);
    setEnv("ALLOW_MAINNET", undefined);
    setEnv("OPERATOR_ATTESTATION_MODE", "signed-challenge");
    setEnv("OPERATOR_ALLOWLIST", ADDR);
    setEnv("AC2_BRIDGE_HOST", "127.0.0.1");
    setEnv("OPERATOR_CHALLENGE_RATE_GLOBAL", "100000");
    expect(checkOperatorGate().ok).toBe(false);
    setEnv("OPERATOR_CHALLENGE_RATE_GLOBAL", undefined);
    setEnv("AC2_BRIDGE_TRUSTED_PROXY_HOPS", "abc");
    expect(checkOperatorGate().ok).toBe(false);
  });

  it("OA-P2-G: 10k store cap holds at max clamped settings", () => {
    expect(maxLiveChallenges(MAX_CHALLENGE_RATE_GLOBAL, MAX_CHALLENGE_TTL_MS)).toBeLessThan(CHALLENGE_STORE_MAX_ENTRIES);
    expect(maxLiveChallenges(600, 120_000)).toBeLessThan(CHALLENGE_STORE_MAX_ENTRIES);
  });

  it("OA-P1-O: isTrustedLocalRequest denies hops>0 and any forwarding header", () => {
    const none = () => undefined;
    expect(isTrustedLocalRequest({ remoteAddress: "127.0.0.1", header: none, trustedProxyHops: 0 })).toBe(true);
    expect(isTrustedLocalRequest({ remoteAddress: "127.0.0.1", header: none, trustedProxyHops: 1 })).toBe(false);
    expect(isTrustedLocalRequest({ remoteAddress: "10.0.0.1", header: none, trustedProxyHops: 0 })).toBe(false);
    for (const h of ["x-forwarded-for", "forwarded", "cf-connecting-ip", "x-real-ip", "true-client-ip", "x-forwarded-host", "x-forwarded-proto", "via", "x-client-ip", "fastly-client-ip"]) {
      expect(isTrustedLocalRequest({ remoteAddress: "127.0.0.1", header: (n) => (n === h ? "" : undefined), trustedProxyHops: 0 }), h).toBe(false);
    }
  });

  it("OA-P1-O: tokenless authorizeOperator honours isLocal=false", () => {
    setEnv("NETWORK", ALGORAND_TESTNET_CAIP2);
    setEnv("ALLOW_MAINNET", undefined);
    setEnv("ALLOW_INSECURE_DEV", "1");
    setEnv("AC2_OPERATOR_TOKEN", undefined);
    expect(authorizeOperator({ headerToken: null, remoteAddress: "127.0.0.1", isLocal: true }).ok).toBe(true);
    expect(authorizeOperator({ headerToken: null, remoteAddress: "127.0.0.1", isLocal: false }).ok).toBe(false);
  });

  it("OA-P3-P: normalizeClientKey maps all loopback to one key", () => {
    for (const a of ["127.0.0.1", "127.3.4.5", "::1", "[::1]", "::ffff:127.0.0.9", "localhost"]) expect(normalizeClientKey(a), a).toBe("loopback");
    expect(normalizeClientKey("10.0.0.1")).toBe("10.0.0.1");
    expect(normalizeClientKey(undefined)).toBe("unknown");
  });

  it("OA-P2-R: checkOperatorGate refuses auto-local when hops > 0", () => {
    setEnv("NETWORK", ALGORAND_TESTNET_CAIP2);
    setEnv("ALLOW_MAINNET", undefined);
    setEnv("ALLOW_INSECURE_DEV", "1");
    setEnv("OPERATOR_ATTESTATION_MODE", "token-lab");
    setEnv("AC2_OPERATOR_TOKEN", "lab-token");
    setEnv("OPERATOR_SIGNDATA_DOMAIN", "mandaterail.pages.dev");
    setEnv("AC2_BRIDGE_AUTO_LOCAL", "true");
    setEnv("AC2_BRIDGE_TRUSTED_PROXY_HOPS", "0");
    expect(checkOperatorGate().ok).toBe(true);
    setEnv("AC2_BRIDGE_TRUSTED_PROXY_HOPS", "1");
    const r = checkOperatorGate();
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/AUTO_LOCAL/);
  });
});

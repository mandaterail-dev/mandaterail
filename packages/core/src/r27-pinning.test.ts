/**
 * R27-P3-4: special IPv6/IPv4 ranges (6to4, Teredo, NAT64, ...) are non-public
 * (ipaddr.js), and a custom fetch can't skip pinning without the explicit
 * test-only flag (refused on mainnet). R27-P3-5: the reconcile indexer check
 * uses the same allowlist, host check and pinning.
 */
import { describe, expect, it } from "vitest";
import { MAINNET_PROFILE, TESTNET_PROFILE } from "./network.js";
import { isNonPublicIp } from "./pinned-fetch.js";
import { indexerTxCheck, providerGuard, twoProviderNoConfirmProof, type SpendReservation } from "./spend-caps.js";

const TN = TESTNET_PROFILE.caip2.slice(9);
const row = { id: "r", payer: "P", amountMicro: 1n, status: "ambiguous", createdMs: 0, updatedMs: 0, txId: "TX1", lastValid: 1000 } as SpendReservation;
const f = (async (input: string | URL) => {
  const u = new URL(String(input));
  if (u.pathname === "/v2/blocks/0") return new Response(JSON.stringify({ "genesis-id": "testnet-v1.0", "genesis-hash": TN }), { status: 200 });
  if (u.pathname === "/health") return new Response(JSON.stringify({ round: 1500 }), { status: 200 });
  return new Response(JSON.stringify({ transaction: { "confirmed-round": 7 } }), { status: 200 });
}) as typeof fetch;
const TP = { ...TESTNET_PROFILE, providerAllowlist: [{ host: "idx-a.example.com", operator: "a" }, { host: "idx-b.example.com", operator: "b" }] };
const MP = { ...MAINNET_PROFILE, providerAllowlist: [{ host: "idx-a.example.com", operator: "a" }, { host: "idx-b.example.com", operator: "b" }] };
const idx = (h: string) => ({ url: `https://${h}`, kind: "indexer" as const });

describe("R27-P3-4 special ranges (ipaddr.js)", () => {
  it("refuses 6to4, Teredo and other special-purpose ranges", () => {
    for (const ip of ["2002:7f00:1::1", "2002::1", "2001:0:4136:e378::1", "2001::1", "2001:db8::1", "2001:10::1", "2001:20::1", "64:ff9b::7f00:1", "64:ff9b:1::1",
      "100::1", "::ffff:8.8.8.8", "::8.8.8.8", "fc00::1", "fd12::1", "fe80::1", "ff02::1", "::", "::1", "3fff::1", "5f00::1", "4000::1", "fe80::1%eth0",
      "192.0.0.8", "192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "192.88.99.1", "100.64.0.1", "169.254.169.254", "240.0.0.1", "255.255.255.255", "0.1.2.3",
      "0x7f000001", "127.1", "017700000001", "not-an-ip", ""]) {
      expect(isNonPublicIp(ip), ip).toBe(true);
    }
  });
  it("accepts global unicast", () => {
    for (const ip of ["93.184.216.34", "8.8.8.8", "2606:4700:4700::1111", "2a00:1450:4001::1"]) expect(isNonPublicIp(ip), ip).toBe(false);
  });
});

describe("R27-P3-4 custom fetch can't skip pinning", () => {
  it("a custom fetch without the explicit flag is refused", () => {
    expect(() => twoProviderNoConfirmProof([idx("idx-a.example.com"), idx("idx-b.example.com")], f, { profile: TP })).toThrow(/custom fetch would skip DNS pinning/);
    expect(() => indexerTxCheck("https://idx-a.example.com", f, { profile: TP })).toThrow(/custom fetch would skip DNS pinning/);
  });
  it("the flag is refused on mainnet", () => {
    expect(() => twoProviderNoConfirmProof([idx("idx-a.example.com"), idx("idx-b.example.com")], f, { profile: MP, unsafeTestCustomFetch: true })).toThrow(/refused on mainnet/);
    expect(() => indexerTxCheck("https://idx-a.example.com", f, { profile: MP, unsafeTestCustomFetch: true })).toThrow(/refused on mainnet/);
  });
  it("the flag with the real fetch is refused", () => {
    expect(() => providerGuard("https://idx-a.example.com", globalThis.fetch, { profile: TP, unsafeTestCustomFetch: true })).toThrow(/only for a custom/);
  });
  it("the real fetch always resolves + pins: a 6to4 / Teredo answer refuses", async () => {
    for (const bad of ["2002:7f00:1::1", "2001:0:1::1"]) {
      const g = providerGuard("https://idx-a.example.com", globalThis.fetch, { profile: TP, resolve: async () => [bad] });
      await expect(g()).rejects.toThrow(/private|refused/);
    }
    const ok = providerGuard("https://idx-a.example.com", globalThis.fetch, { profile: TP, resolve: async () => ["93.184.216.34"] });
    expect(typeof (await ok())).toBe("function");
  });
});

describe("R27-P3-5 reconcile indexer check: allowlist, host check, pinning", () => {
  it("refuses loopback, IP literals, .invalid and hosts off the allowlist", () => {
    for (const u of ["http://127.0.0.1:8980", "http://localhost:8980", "http://[::1]:1", "https://0x7f000001", "https://x.invalid", "https://db.internal", "https://unknown.example.com"]) {
      expect(() => indexerTxCheck(u, f, { profile: TP, unsafeTestCustomFetch: true }), u).toThrow();
    }
    expect(() => indexerTxCheck("http://127.0.0.1:8980", globalThis.fetch, { profile: TESTNET_PROFILE })).toThrow(/loopback/);
  });
  it("the default allowlist accepts the TestNet indexer (real fetch)", () => {
    expect(() => indexerTxCheck("https://testnet-idx.algonode.cloud", globalThis.fetch, { profile: TESTNET_PROFILE })).not.toThrow();
  });
  it("resolves once per check instance; a private answer makes every row unknown", async () => {
    let calls = 0;
    const priv = indexerTxCheck("https://idx-a.example.com", f, { profile: TP, unsafeTestCustomFetch: true, resolve: async () => { calls++; return ["10.0.0.5"]; } });
    expect(await priv(row)).toBe("unknown");
    let ok = 0;
    const good = indexerTxCheck("https://idx-a.example.com", f, { profile: TP, unsafeTestCustomFetch: true, resolve: async () => { ok++; return ["93.184.216.34"]; } });
    expect(await good(row)).toBe("settled");
    expect(await good(row)).toBe("settled");
    expect(ok).toBe(1);
    expect(calls).toBeGreaterThan(0);
  });
});

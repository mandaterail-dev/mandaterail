/**
 * R26-P3-4 host normalization + IP-form / private-suffix refusal, and the
 * run-26 Qwen flags: no caller allowlist override, DNS resolved once and pinned
 * to a public IP.
 */
import http from "node:http";
import type { AddressInfo } from "node:net";
import { describe, expect, it } from "vitest";
import { isForbiddenProviderHost, normalizeProviderHost, TESTNET_PROFILE } from "./network.js";
import { isNonPublicIp, pinnedFetch, resolvePinned } from "./pinned-fetch.js";
import { providerHost, twoProviderNoConfirmProof, type SpendReservation } from "./spend-caps.js";

const TN = TESTNET_PROFILE.caip2.slice(9);
const row = { id: "r", payer: "P", amountMicro: 1n, status: "ambiguous", createdMs: 0, updatedMs: 0, txId: "TX1", lastValid: 1000 } as SpendReservation;
const f = (async (input: string | URL) => {
  const u = new URL(String(input));
  if (u.pathname === "/v2/blocks/0") return new Response(JSON.stringify({ "genesis-id": "testnet-v1.0", "genesis-hash": TN }), { status: 200 });
  if (u.pathname === "/health") return new Response(JSON.stringify({ round: 1500 }), { status: 200 });
  return new Response("{}", { status: 404 });
}) as typeof fetch;
const TP = { ...TESTNET_PROFILE, providerAllowlist: [{ host: "idx-a.example.com", operator: "a" }, { host: "idx-b.example.com", operator: "b" }] };
const idx = (h: string) => ({ url: `https://${h}`, kind: "indexer" as const });

describe("R26-P3-4 provider hosts", () => {
  it("normalizes case, trailing dot, port and brackets", () => {
    expect(normalizeProviderHost("TestNet-IDX.AlgoNode.Cloud.")).toBe("testnet-idx.algonode.cloud");
    expect(normalizeProviderHost("Node.Example.com:8443")).toBe("node.example.com");
    expect(normalizeProviderHost("[::1]:443")).toBe("::1");
    expect(providerHost("https://IDX-A.Example.COM./v2")).toBe("idx-a.example.com");
  });
  it("refuses every IP form and private suffix", () => {
    for (const h of ["0x7f000001", "0X7F000001", "2130706433", "0177.0.0.1", "0x7f.0.0.1", "127.1", "1.2.3.4", "foo.123", "foo.0x1f",
      "printer.local", "db.internal", "nas.home.arpa", "HOME.ARPA.", "x.Local.", "::ffff:127.0.0.1", "[fe80::1]", "a..b", "-a.example", "a_b.example"]) {
      expect(isForbiddenProviderHost(h), h).toBe(true);
    }
    for (const h of ["testnet-idx.algonode.cloud", "TESTNET-IDX.ALGONODE.CLOUD.", "node1.example.com:8443", "0x.example.com", "123abc.example.com"]) expect(isForbiddenProviderHost(h), h).toBe(false);
  });
  it("an allowlisted host matches in any case / with a trailing dot", async () => {
    const r = await twoProviderNoConfirmProof([idx("IDX-A.example.com."), idx("idx-b.EXAMPLE.com")], f, { profile: TP, unsafeTestCustomFetch: true })(row);
    expect(r).toMatchObject({ ok: true, observations: [{ provider: "idx-a.example.com", operator: "a" }, { provider: "idx-b.example.com", operator: "b" }] });
  });
});

describe("run-26 Qwen flags", () => {
  it("a caller-supplied allowlist override is refused (profile only)", () => {
    const opts = { profile: TESTNET_PROFILE, allowlist: [{ host: "evil.example.com", operator: "x" }, { host: "evil2.example.com", operator: "y" }] } as unknown as { profile: typeof TESTNET_PROFILE };
    expect(() => twoProviderNoConfirmProof([idx("evil.example.com"), idx("evil2.example.com")], f, opts)).toThrow(/allowlist overrides are not accepted/);
  });

  it("classifies non-public IPs", () => {
    for (const ip of ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1", "::1", "::", "fe80::1", "fc00::1", "fd12::1", "::ffff:10.0.0.1", "::ffff:7f00:1", "64:ff9b::a00:1", "2001:db8::1", "not-an-ip"]) expect(isNonPublicIp(ip), ip).toBe(true);
    for (const ip of ["8.8.8.8", "1.1.1.1", "2606:4700::1111"]) expect(isNonPublicIp(ip), ip).toBe(false);
  });

  it("resolves once; any private / loopback / link-local answer refuses the proof", async () => {
    let calls = 0;
    const resolve = async (h: string) => { calls++; return h.startsWith("idx-a") ? ["93.184.216.34"] : ["93.184.216.35", "169.254.169.254"]; };
    const r = await twoProviderNoConfirmProof([idx("idx-a.example.com"), idx("idx-b.example.com")], f, { profile: TP, unsafeTestCustomFetch: true, resolve })(row);
    expect(r).toMatchObject({ ok: false, why: expect.stringMatching(/idx-b\.example\.com: resolves to a private/) });
    const ok = await twoProviderNoConfirmProof([idx("idx-a.example.com"), idx("idx-b.example.com")], f, { profile: TP, unsafeTestCustomFetch: true, resolve: async () => { calls++; return ["93.184.216.34"]; } })(row);
    expect(ok).toMatchObject({ ok: true });
    expect(calls).toBe(4); // one lookup per host per proof, never per request
    await expect(resolvePinned("x.example.com", async () => ["127.0.0.1"])).rejects.toThrow(/private/);
    await expect(resolvePinned("x.example.com", async () => [])).rejects.toThrow(/no address/);
    await expect(resolvePinned("x.example.com", async () => { throw new Error("nx"); })).rejects.toThrow(/DNS lookup failed/);
  });

  it("pinnedFetch connects to the pinned IP whatever the URL host says", async () => {
    const srv = http.createServer((req, res) => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ host: req.headers.host, path: req.url })); });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    try {
      const port = (srv.address() as AddressInfo).port;
      // the name does not resolve anywhere; only the pin makes this reach the local server
      const res = await pinnedFetch("127.0.0.1")(`http://never-resolves.invalid:${port}/v2/x`, { headers: { "X-T": "1" } });
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ host: `never-resolves.invalid:${port}`, path: "/v2/x" });
    } finally {
      srv.close();
    }
  });
});

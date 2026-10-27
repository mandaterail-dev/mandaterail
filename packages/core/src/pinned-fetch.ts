/**
 * Qwen flag (run 26), DNS rebinding: a chain provider's host is resolved ONCE,
 * every address must be public (no private / loopback / link-local / CGNAT /
 * multicast / reserved / unique-local / IPv4-mapped forms), and all requests
 * for that observation go to the pinned address (TLS SNI + certificate check
 * still use the host name). A second lookup can't steer a request elsewhere.
 */
import { lookup as dnsLookup } from "node:dns/promises";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import ipaddr from "ipaddr.js";

export class PinnedHostError extends Error {}
export type Resolver = (host: string) => Promise<string[]>;

export const defaultResolver: Resolver = async (host) => (await dnsLookup(host, { all: true, verbatim: true })).map((a) => a.address);

/**
 * R27-P3-4: parsed with ipaddr.js (MIT). Only canonical dotted-quad IPv4 /
 * valid IPv6 is accepted at all; anything ipaddr.js does not classify as
 * plain "unicast" (private, loopback, link-local, CGNAT, multicast, reserved,
 * benchmarking, unique-local, 6to4 2002::/16, Teredo 2001::/32, NAT64,
 * ORCHID, AS112, AMT, discard, documentation, ...) is refused, as is IPv6
 * outside 2000::/3. IPv4-mapped / -compatible IPv6 is refused outright.
 */
const V4_EXTRA_NONPUBLIC: Array<[string, number]> = [
  ["192.0.0.0", 24], ["192.0.2.0", 24], ["198.51.100.0", 24], ["203.0.113.0", 24], ["198.18.0.0", 15], ["192.88.99.0", 24], ["0.0.0.0", 8], ["240.0.0.0", 4],
];
const V6_EXTRA_NONPUBLIC: Array<[string, number]> = [
  ["2001::", 23], ["2001:db8::", 32], ["2002::", 16], ["64:ff9b::", 96], ["64:ff9b:1::", 48], ["100::", 64], ["3fff::", 20], ["5f00::", 16], ["::", 96], ["::ffff:0:0", 96],
];
/** true for every address that is not globally routable unicast. */
export function isNonPublicIp(ip: string): boolean {
  if (typeof ip !== "string") return true;
  if (ipaddr.IPv4.isValidFourPartDecimal(ip)) {
    const a = ipaddr.IPv4.parse(ip);
    if (a.range() !== "unicast") return true;
    return V4_EXTRA_NONPUBLIC.some(([n, l]) => a.match(ipaddr.IPv4.parse(n), l));
  }
  if (!ipaddr.IPv6.isValid(ip) || ip.includes("%")) return true;
  let a: ipaddr.IPv6;
  try {
    a = ipaddr.IPv6.parse(ip);
  } catch {
    return true;
  }
  if (a.isIPv4MappedAddress()) return true;
  if (a.range() !== "unicast") return true;
  if (V6_EXTRA_NONPUBLIC.some(([n, l]) => a.match(ipaddr.IPv6.parse(n), l))) return true;
  return !a.match(ipaddr.IPv6.parse("2000::"), 3);
}

/** Resolve once; refuse if ANY address is non-public; return the first (pinned) one. */
export async function resolvePinned(host: string, resolve: Resolver = defaultResolver): Promise<string> {
  if (net.isIP(host)) throw new PinnedHostError(`${host}: IP literals are not chain providers`);
  let addrs: string[];
  try {
    addrs = await resolve(host);
  } catch {
    throw new PinnedHostError(`${host}: DNS lookup failed`);
  }
  if (!addrs.length) throw new PinnedHostError(`${host}: DNS returned no address`);
  const bad = addrs.filter(isNonPublicIp);
  if (bad.length) throw new PinnedHostError(`${host}: resolves to a private / loopback / link-local address (refused)`);
  return addrs[0]!;
}

/**
 * A minimal fetch (GET + headers + signal) that connects to `ip` for every
 * request, whatever the URL's host. Only for the chain-provider observers.
 */
export function pinnedFetch(ip: string): typeof fetch {
  const family = net.isIPv6(ip) ? 6 : 4;
  return (async (input: string | URL, init?: RequestInit) => {
    const u = new URL(String(input));
    const mod = u.protocol === "https:" ? https : u.protocol === "http:" ? http : null;
    if (!mod) throw new PinnedHostError("pinnedFetch: http(s) only");
    const headers = Object.fromEntries(new Headers(init?.headers ?? {}).entries());
    return await new Promise<Response>((resolve, reject) => {
      const req = mod.request(u, {
        method: init?.method ?? "GET",
        headers,
        signal: init?.signal ?? undefined,
        agent: false,
        lookup: ((_h: string, opts: { all?: boolean }, cb: (...a: unknown[]) => void) => {
          if (opts && opts.all) cb(null, [{ address: ip, family }]);
          else cb(null, ip, family);
        }) as unknown as typeof import("node:dns").lookup,
      }, (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        res.on("data", (c: Buffer) => {
          size += c.length;
          if (size > 1_000_000) { req.destroy(new PinnedHostError("pinnedFetch: response too large")); return; }
          chunks.push(c);
        });
        res.on("end", () => {
          const h = new Headers();
          for (const [k, v] of Object.entries(res.headers)) if (typeof v === "string") h.set(k, v);
          const status = res.statusCode ?? 0;
          const body = status === 204 || status === 304 ? null : Buffer.concat(chunks);
          resolve(new Response(body, { status, headers: h }));
        });
        res.on("error", reject);
      });
      req.on("error", reject);
      req.end();
    });
  }) as typeof fetch;
}

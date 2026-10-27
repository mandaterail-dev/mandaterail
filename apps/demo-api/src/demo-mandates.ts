/**
 * Demo mandate registry for demo-api (internal reviewer run 19 note: unauthenticated
 * POST /demo/mandates into an unbounded map was a DoS risk on the public host).
 *
 *  - bounded: at most DEMO_MANDATES_MAX entries (default 200); oldest
 *    non-pinned entry is evicted when full; entries expire after
 *    DEMO_MANDATES_TTL_MS (default 1 h); body at most DEMO_MANDATES_MAX_BODY
 *    bytes (default 8 KiB); id at most 128 safe chars.
 *  - gated: DEMO_MANDATES_WRITE = "loopback" (default) | "off".
 *    "loopback" accepts only direct loopback peers with no forwarding
 *    headers (so anything through the public nginx is refused). MainNet: always
 *    off (isTrustedLocalRequest is also false on MainNet, T9).
 *  The seed mandate is pinned (never evicted / expired). GET stays public.
 */
import type { Context, Hono } from "hono";
import type { IntentMandate } from "@mandaterail/schema";
import { isMainnetProfile, isTrustedLocalRequest } from "@mandaterail/core";

export type DemoMandateLimits = { maxEntries: number; ttlMs: number; maxBodyBytes: number };
export const DEFAULT_DEMO_MANDATE_LIMITS: DemoMandateLimits = { maxEntries: 200, ttlMs: 3_600_000, maxBodyBytes: 8192 };
const ID_RE = /^[A-Za-z0-9._:-]{1,128}$/;

function posInt(v: string | undefined, d: number, max: number): number {
  const n = Number(v);
  return Number.isInteger(n) && n > 0 ? Math.min(n, max) : d;
}

export function demoMandateLimitsFromEnv(env: NodeJS.ProcessEnv = process.env): DemoMandateLimits {
  return {
    maxEntries: posInt(env.DEMO_MANDATES_MAX, DEFAULT_DEMO_MANDATE_LIMITS.maxEntries, 10_000),
    ttlMs: posInt(env.DEMO_MANDATES_TTL_MS, DEFAULT_DEMO_MANDATE_LIMITS.ttlMs, 24 * 3_600_000),
    maxBodyBytes: posInt(env.DEMO_MANDATES_MAX_BODY, DEFAULT_DEMO_MANDATE_LIMITS.maxBodyBytes, 65_536),
  };
}

export type DemoWriteMode = "loopback" | "off";
export function demoWriteMode(env: NodeJS.ProcessEnv = process.env): DemoWriteMode {
  if (isMainnetProfile(env.NETWORK)) return "off";
  const v = (env.DEMO_MANDATES_WRITE ?? "").trim().toLowerCase();
  return v === "off" || v === "false" || v === "0" ? "off" : "loopback";
}

export class DemoMandateStore {
  private readonly m = new Map<string, { mandate: IntentMandate; exp: number; pinned: boolean }>();
  constructor(readonly limits: DemoMandateLimits = DEFAULT_DEMO_MANDATE_LIMITS, private readonly now: () => number = Date.now) {}
  get size(): number {
    this.sweep();
    return this.m.size;
  }
  private sweep() {
    const t = this.now();
    for (const [k, v] of this.m) if (!v.pinned && v.exp <= t) this.m.delete(k);
  }
  pin(m: IntentMandate) {
    this.m.set(m.id, { mandate: m, exp: Infinity, pinned: true });
  }
  get(id: string): IntentMandate | undefined {
    this.sweep();
    return this.m.get(id)?.mandate;
  }
  has(id: string): boolean {
    return this.get(id) !== undefined;
  }
  /** false when the id is pinned (seed can't be overwritten). */
  set(m: IntentMandate): boolean {
    this.sweep();
    if (this.m.get(m.id)?.pinned) return false;
    this.m.delete(m.id);
    while (this.m.size >= this.limits.maxEntries) {
      const oldest = [...this.m].find(([, v]) => !v.pinned);
      if (!oldest) return false;
      this.m.delete(oldest[0]);
    }
    this.m.set(m.id, { mandate: m, exp: this.now() + this.limits.ttlMs, pinned: false });
    return true;
  }
}

export function mountDemoMandates(
  app: Hono<any>,
  store: DemoMandateStore,
  opts: { mode?: () => DemoWriteMode; remoteAddress: (c: Context) => string | undefined },
) {
  const mode = opts.mode ?? (() => demoWriteMode());
  app.get("/demo/mandates/:id", (c) => {
    const m = store.get(c.req.param("id"));
    if (!m) return c.json({ error: "not_found" }, 404);
    return c.json(m);
  });
  app.post("/demo/mandates", async (c) => {
    if (mode() === "off") return c.json({ error: "demo_mandates_disabled" }, 403);
    const local = isTrustedLocalRequest({ remoteAddress: opts.remoteAddress(c), header: (n) => c.req.header(n), trustedProxyHops: 0 });
    if (!local) return c.json({ error: "demo_mandates_loopback_only" }, 403);
    const len = Number(c.req.header("content-length") ?? NaN);
    if (Number.isFinite(len) && len > store.limits.maxBodyBytes) return c.json({ error: "body_too_large" }, 413);
    const raw = await c.req.arrayBuffer().catch(() => null);
    if (!raw) return c.json({ error: "invalid_json" }, 400);
    if (raw.byteLength > store.limits.maxBodyBytes) return c.json({ error: "body_too_large" }, 413);
    let body: unknown;
    try {
      body = JSON.parse(new TextDecoder().decode(raw));
    } catch {
      body = null;
    }
    if (!body || typeof body !== "object" || Array.isArray(body)) return c.json({ error: "invalid_json" }, 400);
    const given = (body as { id?: unknown }).id;
    if (given !== undefined && (typeof given !== "string" || !ID_RE.test(given))) return c.json({ error: "invalid_id" }, 400);
    const id = typeof given === "string" ? given : crypto.randomUUID();
    const mandate = { ...(body as object), id } as IntentMandate;
    if (!store.set(mandate)) return c.json({ error: "id_reserved" }, 409);
    return c.json(mandate, 201);
  });
}

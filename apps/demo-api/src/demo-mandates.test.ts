import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Hono } from "hono";
import { ALGORAND_MAINNET_CAIP2 } from "@mandaterail/core";
import { DemoMandateStore, demoMandateLimitsFromEnv, demoWriteMode, mountDemoMandates } from "./demo-mandates.js";

const KEYS = ["NETWORK", "ALLOW_MAINNET", "DEMO_MANDATES_WRITE", "AC2_BRIDGE_TRUSTED_PROXY_HOPS", "TRUSTED_PROXY_HOPS"];
const saved: Record<string, string | undefined> = {};
beforeEach(() => { for (const k of KEYS) { saved[k] = process.env[k]; delete process.env[k]; } });
afterEach(() => { for (const k of KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; } });

function mk(limits = { maxEntries: 3, ttlMs: 1000, maxBodyBytes: 256 }) {
  const clock = { t: 1_000_000 };
  const store = new DemoMandateStore(limits, () => clock.t);
  store.pin({ id: "seed" } as never);
  const app = new Hono();
  mountDemoMandates(app, store, { remoteAddress: (c) => c.req.header("x-test-ip") ?? "127.0.0.1" });
  const post = (body: unknown, h: Record<string, string> = {}) =>
    app.request("/demo/mandates", { method: "POST", headers: { "content-type": "application/json", ...h }, body: typeof body === "string" ? body : JSON.stringify(body) });
  return { app, store, clock, post };
}

describe("demo-api POST /demo/mandates (run 19 DoS note)", () => {
  it("loopback direct peer: 201; public peer or proxied (nginx) request: 403", async () => {
    const { post } = mk();
    expect((await post({ id: "a" })).status).toBe(201);
    expect((await post({ id: "b" }, { "x-test-ip": "203.0.113.5" })).status).toBe(403);
    const viaProxy = await post({ id: "c" }, { "x-forwarded-for": "203.0.113.5" });
    expect(viaProxy.status).toBe(403);
    expect(await viaProxy.json()).toEqual({ error: "demo_mandates_loopback_only" });
  });
  it("off on MainNet regardless of DEMO_MANDATES_WRITE; off when DEMO_MANDATES_WRITE=off", async () => {
    process.env.DEMO_MANDATES_WRITE = "off";
    expect(demoWriteMode()).toBe("off");
    expect((await mk().post({ id: "a" })).status).toBe(403);
    process.env.DEMO_MANDATES_WRITE = "loopback";
    process.env.NETWORK = ALGORAND_MAINNET_CAIP2;
    expect(demoWriteMode()).toBe("off");
    expect((await mk().post({ id: "a" })).status).toBe(403);
  });
  it("size cap (413), bad JSON/id (400), seed can't be overwritten (409)", async () => {
    const { post, store } = mk();
    expect((await post({ id: "big", pad: "x".repeat(400) })).status).toBe(413);
    expect((await post("not json")).status).toBe(400);
    expect((await post([1, 2])).status).toBe(400);
    expect((await post({ id: "../../etc" })).status).toBe(400);
    expect((await post({ id: "seed", evil: true })).status).toBe(409);
    expect(store.get("seed")).toEqual({ id: "seed" });
  });
  it("entry cap evicts oldest (seed pinned); TTL expires entries", async () => {
    const { post, store, clock, app } = mk();
    for (const id of ["a", "b", "c", "d"]) expect((await post({ id })).status).toBe(201);
    expect(store.size).toBe(3); // seed + 2 newest
    expect(store.has("a")).toBe(false);
    expect(store.has("b")).toBe(false);
    expect(store.has("seed")).toBe(true);
    clock.t += 1001;
    expect((await app.request("/demo/mandates/d")).status).toBe(404);
    expect(store.size).toBe(1);
    expect((await app.request("/demo/mandates/seed")).status).toBe(200);
  });
  it("limits from env are clamped", () => {
    expect(demoMandateLimitsFromEnv({})).toEqual({ maxEntries: 200, ttlMs: 3_600_000, maxBodyBytes: 8192 });
    expect(demoMandateLimitsFromEnv({ DEMO_MANDATES_MAX: "999999", DEMO_MANDATES_TTL_MS: "-1", DEMO_MANDATES_MAX_BODY: "1e9" })).toEqual({ maxEntries: 10_000, ttlMs: 3_600_000, maxBodyBytes: 65_536 });
  });
});

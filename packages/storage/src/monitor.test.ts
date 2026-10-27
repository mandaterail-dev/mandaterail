import { describe, expect, it } from "vitest";
import { MonitorConfigError, monitorSelfFailure, monitorUrlKey, runMonitor } from "./monitor.js";

const clean = { pending: 0, ambiguous: 0, oldestAgeMs: null };
function fakeFetch(map: Record<string, number | Error>, posts: Array<{ url: string; init?: RequestInit }> = []) {
  return (async (url: string, init?: RequestInit) => {
    if (init?.method === "POST") {
      posts.push({ url, init });
      const s = map[url] ?? 200;
      if (s instanceof Error) throw s;
      return new Response("ok", { status: s });
    }
    const s = map[url] ?? 200;
    if (s instanceof Error) throw s;
    return new Response("{}", { status: s });
  }) as unknown as typeof fetch;
}
const sink = () => {
  const out: string[] = [];
  const err: string[] = [];
  return { out, err, log: (l: string) => out.push(l), errf: (l: string) => err.push(l) };
};

describe("R21-P3-1 monitor", () => {
  it("empty MONITOR_HEALTH_URLS is a config error, not healthy", async () => {
    for (const v of [undefined, "", " , "]) {
      await expect(runMonitor({ env: { MONITOR_HEALTH_URLS: v }, store: "s", olderThanMin: 30, stale: async () => clean, fetchImpl: fakeFetch({}) })).rejects.toThrow(MonitorConfigError);
    }
  });

  it("results are keyed by URL (two paths on one host stay distinct; no query/userinfo)", async () => {
    const s = sink();
    const a = "https://h.example/health";
    const b = "https://h.example/bridge/health?token=abc";
    const r = await runMonitor({ env: { MONITOR_HEALTH_URLS: `${a},${b}` }, store: "s", olderThanMin: 30, stale: async () => clean, fetchImpl: fakeFetch({ [b]: 503 }), log: s.log, err: s.errf });
    expect(r.health).toEqual({ "https://h.example/health": 200, "https://h.example/bridge/health": 503 });
    expect(r.exitCode).toBe(2);
    expect(s.err.join("\n")).not.toContain("token=abc");
    expect(monitorUrlKey("https://u:p@x.example/a?q=1")).toBe("https://x.example/a");
  });

  it("stale rows alone exit non-zero; healthy + clean exits 0 and logs no-pager", async () => {
    const s = sink();
    const env = { MONITOR_HEALTH_URLS: "https://h.example/health" };
    const r = await runMonitor({ env, store: "s", olderThanMin: 30, stale: async () => ({ pending: 1, ambiguous: 0, oldestAgeMs: 99 }), fetchImpl: fakeFetch({}), log: s.log, err: s.errf });
    expect(r).toMatchObject({ ok: false, exitCode: 2, pager: "not-configured" });
    expect(s.err[0]).toMatch(/^ALERT .*stale spend rows: 1 pending/);
    expect(s.err.join("\n")).toMatch(/no pager configured/);
    const s2 = sink();
    const ok = await runMonitor({ env, store: "s", olderThanMin: 30, stale: async () => clean, fetchImpl: fakeFetch({}), log: s2.log, err: s2.errf });
    expect(ok).toMatchObject({ ok: true, exitCode: 0 });
    expect(JSON.parse(s2.out[0]!)).toMatchObject({ ok: true, pager: "not-configured" });
    expect(s2.err.join("\n")).toMatch(/no pager configured/);
  });

  it("pager: POSTs on alert only, generic/slack/ntfy formats, URL never printed, failure reported", async () => {
    const hook = "https://hooks.example/services/SECRET123";
    for (const [fmt, ct] of [["json", "application/json"], ["slack", "application/json"], ["ntfy", "text/plain"]] as const) {
      const posts: Array<{ url: string; init?: RequestInit }> = [];
      const s = sink();
      const env = { MONITOR_HEALTH_URLS: "https://h.example/health", MONITOR_PAGER_WEBHOOK_URL: hook, MONITOR_PAGER_FORMAT: fmt };
      const r = await runMonitor({ env, store: "s", olderThanMin: 30, stale: async () => clean, fetchImpl: fakeFetch({ "https://h.example/health": new Error("down") }, posts), log: s.log, err: s.errf });
      expect(r).toMatchObject({ pager: "sent", exitCode: 2 });
      expect(posts).toHaveLength(1);
      expect(posts[0]!.url).toBe(hook);
      expect(String((posts[0]!.init!.headers as Record<string, string>)["Content-Type"])).toContain(ct);
      const body = String(posts[0]!.init!.body);
      if (fmt === "ntfy") expect(body).toMatch(/^MandateRail ALERT/);
      else expect(JSON.parse(body).text).toMatch(/MandateRail ALERT .*health https:\/\/h.example\/health -> error/);
      if (fmt === "slack") expect(Object.keys(JSON.parse(body))).toEqual(["text"]);
      expect(s.out.concat(s.err).join("\n")).not.toContain("SECRET123");
    }
    // healthy: no POST
    const posts: Array<{ url: string }> = [];
    await runMonitor({ env: { MONITOR_HEALTH_URLS: "https://h.example/health", MONITOR_PAGER_WEBHOOK_URL: hook }, store: "s", olderThanMin: 30, stale: async () => clean, fetchImpl: fakeFetch({}, posts), log: () => undefined, err: () => undefined });
    expect(posts).toHaveLength(0);
    // pager down: still exit 2, reported
    const s = sink();
    const r = await runMonitor({ env: { MONITOR_HEALTH_URLS: "https://h.example/health", MONITOR_PAGER_WEBHOOK_URL: hook }, store: "s", olderThanMin: 30, stale: async () => ({ pending: 0, ambiguous: 2, oldestAgeMs: 1 }), fetchImpl: fakeFetch({ [hook]: 500 }), log: s.log, err: s.errf });
    expect(r).toMatchObject({ pager: "failed", exitCode: 2 });
    expect(s.err.join("\n")).toMatch(/pager POST failed/);
    // bad pager config
    await expect(runMonitor({ env: { MONITOR_HEALTH_URLS: "https://h.example/health", MONITOR_PAGER_WEBHOOK_URL: "http://remote.example/x" }, store: "s", olderThanMin: 30, stale: async () => clean })).rejects.toThrow(/https/);
    await expect(runMonitor({ env: { MONITOR_HEALTH_URLS: "https://h.example/health", MONITOR_PAGER_WEBHOOK_URL: hook, MONITOR_PAGER_FORMAT: "sms" }, store: "s", olderThanMin: 30, stale: async () => clean })).rejects.toThrow(/FORMAT/);
  });
});

describe("R22 monitor", () => {
  const env = { MONITOR_HEALTH_URLS: "https://a.example/health", MONITOR_PAGER_WEBHOOK_URL: "https://pager.example/hook" };
  it("R22-P3-3: a failing stale-row query (DB down) pages and exits 2", async () => {
    const posts: Array<{ url: string; init?: RequestInit }> = [];
    const s = sink();
    const r = await runMonitor({ env, store: "s", olderThanMin: 30, stale: async () => { throw Object.assign(new Error("connect ECONNREFUSED postgres://u:secret@h/db"), { code: "ECONNREFUSED" }); }, fetchImpl: fakeFetch({}, posts), log: s.log, err: s.errf });
    expect(r.exitCode).toBe(2);
    expect(r.pager).toBe("sent");
    expect(r.reasons.join()).toMatch(/monitor self-failure: .*ECONNREFUSED/);
    expect(posts).toHaveLength(1);
    expect(s.err.join("\n") + String(posts[0]!.init?.body)).not.toMatch(/secret|postgres:\/\//);
  });
  it("R22-P3-3: monitorSelfFailure pages and exits 2 (and still exits 2 with no pager)", async () => {
    const posts: Array<{ url: string; init?: RequestInit }> = [];
    const s = sink();
    const r = await monitorSelfFailure({ env, store: "s", error: new TypeError("x"), fetchImpl: fakeFetch({}, posts), err: s.errf });
    expect(r).toMatchObject({ exitCode: 2, pager: "sent" });
    expect(posts).toHaveLength(1);
    const r2 = await monitorSelfFailure({ env: {}, store: "s", error: new Error("x"), fetchImpl: fakeFetch({}), err: s.errf });
    expect(r2).toMatchObject({ exitCode: 2, pager: "not-configured" });
  });
  it("R22-P3-4: colliding URL keys and URLs with credentials are config errors", async () => {
    const st = async () => clean;
    await expect(runMonitor({ env: { MONITOR_HEALTH_URLS: "https://a.example/health?x=1,https://a.example/health?x=2" }, store: "s", olderThanMin: 30, stale: st, fetchImpl: fakeFetch({}) })).rejects.toThrow(/same key/);
    await expect(runMonitor({ env: { MONITOR_HEALTH_URLS: "https://a.example/health,https://a.example/health#f" }, store: "s", olderThanMin: 30, stale: st, fetchImpl: fakeFetch({}) })).rejects.toThrow(/same key/);
    await expect(runMonitor({ env: { MONITOR_HEALTH_URLS: "https://u:p@a.example/health" }, store: "s", olderThanMin: 30, stale: st, fetchImpl: fakeFetch({}) })).rejects.toThrow(/credentials/);
    const ok = await runMonitor({ env: { MONITOR_HEALTH_URLS: "https://a.example/health,https://a.example/ready" }, store: "s", olderThanMin: 30, stale: st, fetchImpl: fakeFetch({}), log: () => undefined, err: () => undefined });
    expect(ok.exitCode).toBe(0);
  });
});

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { closeStateTestBackend, prepareStateTestBackend, stateTestBackend, stateTestBackendKind } from "@mandaterail/storage/testing";

// R19-P3-5: real Postgres/Redis under scripts/with-state-services.sh.
beforeAll(prepareStateTestBackend);
afterAll(closeStateTestBackend);
it("R19-P3-5: state backend for this run matches the environment", () => {
  expect(stateTestBackendKind()).toBe(!process.env.MR_TEST_PG_URL ? "memory" : process.env.MR_TEST_REDIS_URL ? "redis+postgres" : "postgres");
  expect(Boolean(stateTestBackend())).toBe(Boolean(process.env.MR_TEST_PG_URL));
});
import algosdk from "algosdk";
import { ALGORAND_MAINNET_CAIP2, ALGORAND_TESTNET_CAIP2, checkOperatorGate, encodeAttestationHeader, signRequesterRequest } from "@mandaterail/core";
import { createBridgeApp, REQUESTER_TOKEN_HEADER } from "./app.js";
import { HttpAc2BridgeSigner } from "@mandaterail/ac2-client";
import { Ac2BridgeClient } from "@mandaterail/sdk";

const op = algosdk.generateAccount();
const OP = op.addr.toString();
const ENV_KEYS = [
  "NETWORK", "ALLOW_MAINNET", "ALLOW_INSECURE_DEV", "AC2_BRIDGE_AUTO_LOCAL", "ALGORAND_MNEMONIC",
  "OPERATOR_ATTESTATION_MODE", "OPERATOR_ALLOWLIST", "OPERATOR_SIGNDATA_DOMAIN", "AC2_OPERATOR_TOKEN",
  "OPERATOR_CHALLENGE_RATE_PER_IP", "OPERATOR_CHALLENGE_RATE_GLOBAL", "AC2_BRIDGE_TRUSTED_PROXY_HOPS",
  "OPERATOR_CHALLENGE_TTL_MS", "AC2_BRIDGE_HOST", "REQUESTER_ALLOWLIST", "AC2_PAIRED",
  "AC2_BRIDGE_MAX_PENDING", "AC2_BRIDGE_PENDING_TTL_MS", "AC2_BRIDGE_RETENTION_MS", "AC2_BRIDGE_SIGN_RATE_PER_MIN", "AC2_BRIDGE_SIGN_RATE_PER_CLIENT", "AC2_BRIDGE_MAX_PENDING_PER_CLIENT",
];
const saved: Record<string, string | undefined> = {};
beforeEach(() => {
  for (const k of ENV_KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
  process.env.NETWORK = ALGORAND_TESTNET_CAIP2;
  process.env.OPERATOR_ATTESTATION_MODE = "signed-challenge";
  process.env.OPERATOR_ALLOWLIST = OP;
  process.env.OPERATOR_SIGNDATA_DOMAIN = "mandaterail.pages.dev"; // OA-P2-Q: always required
});
afterEach(() => {
  for (const k of ENV_KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
});

/** Remote address comes from the x-test-ip header (default loopback). */
function make(now?: () => number) {
  return createBridgeApp({ remoteAddress: (c) => c.req.header("x-test-ip") ?? "127.0.0.1", now, backend: stateTestBackend() });
}
type App = ReturnType<typeof make>["app"];

async function json(res: Response) { return (await res.json()) as Record<string, any>; }

async function attest(app: App, action: string, id: string, ip = "127.0.0.1") {
  const res = await app.request(`/operator/challenge?action=${action}&id=${id}`, { headers: { "x-test-ip": ip } });
  expect(res.status).toBe(200);
  const ch = await json(res);
  const sig = algosdk.signBytes(new TextEncoder().encode(ch.message), op.sk);
  return encodeAttestationHeader({ nonce: ch.nonce, address: OP, format: "algosdk", signature: Buffer.from(sig).toString("base64") });
}

async function queue(app: App) {
  const res = await app.request("/sign", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ message: "hello" }) });
  expect(res.status).toBe(202);
  return json(res);
}

describe("ac2-bridge routes (signed-challenge)", () => {
  it("challenge: no-store, 400 malformed, no pending-id oracle", async () => {
    const { app } = make();
    const r1 = await app.request("/operator/challenge?action=approve&id=does-not-exist");
    expect(r1.status).toBe(200);
    expect(r1.headers.get("cache-control")).toBe("no-store");
    const r2 = await app.request("/operator/challenge?action=approve&id=bad%20id!");
    expect(r2.status).toBe(400);
    expect(r2.headers.get("cache-control")).toBe("no-store");
    const r3 = await app.request("/operator/challenge?action=nope&id=x");
    expect(r3.status).toBe(400);
    // unknown id only fails after auth, with 404
    const ev = await attest(app, "approve", "does-not-exist");
    const r4 = await app.request("/approve/does-not-exist", { method: "POST", headers: { "x-mandaterail-operator-attestation": ev, "content-type": "application/json" }, body: JSON.stringify({ signature: "x" }) });
    expect(r4.status).toBe(404);
  });

  it("R19 open item: AC2_PAIRED=true is a status label only; it grants no auth", async () => {
    process.env.AC2_PAIRED = "true";
    const { app } = make();
    expect(await json(await app.request("/pair/status"))).toEqual({ paired: true, mode: "manual" });
    expect((await app.request("/pending")).status).toBe(401);
    const a = await json(await app.request("/sign", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ message: "x" }) }));
    expect((await app.request(`/approve/${a.id}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ signature: "c2ln" }) })).status).toBe(401);
    expect((await app.request(`/reject/${a.id}`, { method: "POST" })).status).toBe(401);
    expect(await json(await app.request(`/requests/${a.id}/status`, { headers: { "x-mandaterail-requester-token": a.requesterToken } }))).toMatchObject({ status: "pending" });
    // off-box /sign is still refused in signed-challenge mode
    expect((await app.request("/sign", { method: "POST", headers: { "content-type": "application/json", "x-test-ip": "203.0.113.9" }, body: JSON.stringify({ message: "x" }) })).status).not.toBe(202);
  });

  it("/pending requires operator auth and is no-store", async () => {
    const { app } = make();
    const r1 = await app.request("/pending");
    expect(r1.status).toBe(401);
    expect(r1.headers.get("cache-control")).toBe("no-store");
    const ev = await attest(app, "list", "pending");
    const r2 = await app.request("/pending", { headers: { "x-mandaterail-operator-attestation": ev } });
    expect(r2.status).toBe(200);
    expect(r2.headers.get("cache-control")).toBe("no-store");
    // replay refused
    const r3 = await app.request("/pending", { headers: { "x-mandaterail-operator-attestation": ev } });
    expect(r3.status).toBe(401);
  });

  it("approve then approve/reject again -> 409; rejected can never be approved", async () => {
    const { app } = make();
    const a = await queue(app);
    const h = async (action: string, id: string) => ({ "x-mandaterail-operator-attestation": await attest(app, action, id), "content-type": "application/json" });
    const ok = await app.request(`/approve/${a.id}`, { method: "POST", headers: await h("approve", a.id), body: JSON.stringify({ signature: "c2ln", publicKey: "cGs=" }) });
    expect(ok.status).toBe(200);
    expect(ok.headers.get("cache-control")).toBe("no-store");
    expect((await app.request(`/approve/${a.id}`, { method: "POST", headers: await h("approve", a.id), body: JSON.stringify({ signature: "c2ln" }) })).status).toBe(409);
    expect((await app.request(`/reject/${a.id}`, { method: "POST", headers: await h("reject", a.id) })).status).toBe(409);

    const b = await queue(app);
    expect((await app.request(`/reject/${b.id}`, { method: "POST", headers: await h("reject", b.id) })).status).toBe(200);
    expect((await app.request(`/approve/${b.id}`, { method: "POST", headers: await h("approve", b.id), body: JSON.stringify({ signature: "c2ln" }) })).status).toBe(409);
    expect((await app.request(`/reject/${b.id}`, { method: "POST", headers: await h("reject", b.id) })).status).toBe(409);
  });

  it("useLocal without auto-local -> 400", async () => {
    const { app } = make();
    const a = await queue(app);
    const res = await app.request(`/approve/${a.id}`, {
      method: "POST",
      headers: { "x-mandaterail-operator-attestation": await attest(app, "approve", a.id), "content-type": "application/json" },
      body: JSON.stringify({ useLocal: true }),
    });
    expect(res.status).toBe(400);
    expect((await json(res)).error).toBe("use_local_disabled");
  });

  it("requester status flow: token required, wrong token 404, approved returns signature", async () => {
    const { app } = make();
    const a = await queue(app);
    expect(typeof a.requesterToken).toBe("string");
    expect(a.requesterToken.length).toBeGreaterThanOrEqual(43);
    const url = `/requests/${a.id}/status`;
    const none = await app.request(url);
    expect(none.status).toBe(401);
    expect(none.headers.get("cache-control")).toBe("no-store");
    expect((await app.request(url, { headers: { [REQUESTER_TOKEN_HEADER]: "wrong" } })).status).toBe(404);
    expect((await app.request(`/requests/nope/status`, { headers: { [REQUESTER_TOKEN_HEADER]: a.requesterToken } })).status).toBe(404);
    const p = await app.request(url, { headers: { [REQUESTER_TOKEN_HEADER]: a.requesterToken } });
    expect(p.status).toBe(200);
    expect(await json(p)).toEqual({ id: a.id, status: "pending" });
    // another request's token cannot read this one
    const b = await queue(app);
    expect((await app.request(url, { headers: { [REQUESTER_TOKEN_HEADER]: b.requesterToken } })).status).toBe(404);

    await app.request(`/approve/${a.id}`, {
      method: "POST",
      headers: { "x-mandaterail-operator-attestation": await attest(app, "approve", a.id), "content-type": "application/json" },
      body: JSON.stringify({ signature: "c2ln", publicKey: "cGs=", address: OP }),
    });
    const done = await json(await app.request(url, { headers: { [REQUESTER_TOKEN_HEADER]: a.requesterToken } }));
    expect(done).toEqual({ id: a.id, status: "approved", signature: "c2ln", publicKey: "cGs=", address: OP });
    expect(done.message).toBeUndefined();
  });

  it("rate limit: per-IP 429 with Retry-After; malformed ids not counted; other IP ok", async () => {
    process.env.OPERATOR_CHALLENGE_RATE_PER_IP = "3";
    process.env.OPERATOR_CHALLENGE_RATE_GLOBAL = "5";
    const { app } = make();
    for (let i = 0; i < 5; i++) expect((await app.request("/operator/challenge?action=approve&id=bad%20id", { headers: { "x-test-ip": "10.0.0.1" } })).status).toBe(400);
    for (let i = 0; i < 3; i++) expect((await app.request("/operator/challenge?action=approve&id=x", { headers: { "x-test-ip": "10.0.0.1" } })).status).toBe(200);
    const limited = await app.request("/operator/challenge?action=approve&id=x", { headers: { "x-test-ip": "10.0.0.1" } });
    expect(limited.status).toBe(429);
    expect(limited.headers.get("retry-after")).toBe("60");
    expect((await app.request("/operator/challenge?action=approve&id=x", { headers: { "x-test-ip": "10.0.0.2" } })).status).toBe(200);
    expect((await app.request("/operator/challenge?action=approve&id=x", { headers: { "x-test-ip": "10.0.0.2" } })).status).toBe(200);
    // global cap (5) reached
    expect((await app.request("/operator/challenge?action=approve&id=x", { headers: { "x-test-ip": "10.0.0.3" } })).status).toBe(429);
  });

  it("X-Forwarded-For is ignored unless AC2_BRIDGE_TRUSTED_PROXY_HOPS is set", async () => {
    process.env.OPERATOR_CHALLENGE_RATE_PER_IP = "1";
    const { app } = make();
    const req = (xff: string) => app.request("/operator/challenge?action=list&id=pending", { headers: { "x-test-ip": "10.9.9.9", "x-forwarded-for": xff } });
    expect((await req("1.1.1.1")).status).toBe(200);
    expect((await req("2.2.2.2")).status).toBe(429);

    process.env.AC2_BRIDGE_TRUSTED_PROXY_HOPS = "1";
    const { app: app2 } = make();
    const req2 = (xff: string) => app2.request("/operator/challenge?action=list&id=pending", { headers: { "x-test-ip": "10.9.9.9", "x-forwarded-for": xff } });
    expect((await req2("spoof, 1.1.1.1")).status).toBe(200);
    expect((await req2("spoof2, 2.2.2.2")).status).toBe(200);
    expect((await req2("other, 1.1.1.1")).status).toBe(429);
  });

  it("POST /sign queue is loopback-only in signed-challenge mode", async () => {
    const { app } = make();
    const res = await app.request("/sign", { method: "POST", headers: { "content-type": "application/json", "x-test-ip": "10.0.0.5" }, body: JSON.stringify({ message: "x" }) });
    expect(res.status).toBe(401);
  });
});

describe("ac2-bridge routes (TestNet token-lab)", () => {
  it("requester status allows loopback without token; non-loopback needs token", async () => {
    process.env.OPERATOR_ATTESTATION_MODE = "token-lab";
    process.env.ALLOW_INSECURE_DEV = "1";
    const { app } = make();
    const a = await queue(app);
    const lo = await app.request(`/requests/${a.id}/status`);
    expect(lo.status).toBe(200);
    expect((await app.request(`/requests/${a.id}/status`, { headers: { "x-test-ip": "10.0.0.7" } })).status).toBe(401);
    expect((await app.request("/operator/challenge?action=list&id=pending")).status).toBe(404);
  });
});

async function challengeFor(app: App, action: string, id: string) {
  return json(await app.request(`/operator/challenge?action=${action}&id=${id}`));
}

describe("operator auth negative route tests (401)", () => {
  const routes = async (app: App, id: string) => [
    { action: "approve", id, req: (h: Record<string, string>) => app.request(`/approve/${id}`, { method: "POST", headers: { ...h, "content-type": "application/json" }, body: JSON.stringify({ signature: "c2ln" }) }) },
    { action: "reject", id, req: (h: Record<string, string>) => app.request(`/reject/${id}`, { method: "POST", headers: h }) },
    { action: "list", id: "pending", req: (h: Record<string, string>) => app.request("/pending", { headers: h }) },
  ];

  it("forged signature -> 401 on approve, reject, /pending", async () => {
    const { app } = make();
    const a = await queue(app);
    for (const r of await routes(app, a.id)) {
      const ch = await challengeFor(app, r.action, r.id);
      const forged = encodeAttestationHeader({ nonce: ch.nonce, address: OP, format: "algosdk", signature: Buffer.alloc(64, 7).toString("base64") });
      const res = await r.req({ "x-mandaterail-operator-attestation": forged });
      expect(res.status, r.action).toBe(401);
    }
    const st = await json(await app.request(`/requests/${a.id}/status`, { headers: { [REQUESTER_TOKEN_HEADER]: a.requesterToken } }));
    expect(st.status).toBe("pending");
  });

  it("valid signature from a non-allowlisted signer -> 401 on approve, reject, /pending", async () => {
    const { app } = make();
    const a = await queue(app);
    const stranger = algosdk.generateAccount();
    for (const r of await routes(app, a.id)) {
      const ch = await challengeFor(app, r.action, r.id);
      const sig = algosdk.signBytes(new TextEncoder().encode(ch.message), stranger.sk);
      const ev = encodeAttestationHeader({ nonce: ch.nonce, address: stranger.addr.toString(), format: "algosdk", signature: Buffer.from(sig).toString("base64") });
      const res = await r.req({ "x-mandaterail-operator-attestation": ev });
      expect(res.status, r.action).toBe(401);
    }
    // item untouched
    const st = await json(await app.request(`/requests/${a.id}/status`, { headers: { [REQUESTER_TOKEN_HEADER]: a.requesterToken } }));
    expect(st.status).toBe("pending");
  });
});

describe("OA-P2-I pending queue: cap, TTL, eviction, /sign rate limit", () => {
  const st = (app: App, a: Record<string, any>) => app.request(`/requests/${a.id}/status`, { headers: { [REQUESTER_TOKEN_HEADER]: a.requesterToken } });

  it("cap: 503 when full; uncollected results are never evicted; collected ones are", async () => {
    process.env.AC2_BRIDGE_MAX_PENDING = "2";
    process.env.AC2_BRIDGE_MAX_PENDING_PER_CLIENT = "2";
    const { app, queueStore } = make();
    // R19-P3-5: ask the queue store itself (memory or Postgres), not the memory map
    const has = async (id: string) => (await queueStore.get(id, Date.now())) !== null;
    const a = await queue(app);
    const b = await queue(app);
    // OA-P3-P: 127.0.0.3 is the same loopback client key, so with 2 pending
    // the per-client cap trips first.
    const signReq = () => app.request("/sign", { method: "POST", headers: { "content-type": "application/json", "x-test-ip": "127.0.0.3" }, body: JSON.stringify({ message: "x" }) });
    const capped = await signReq();
    expect(capped.status).toBe(429);
    expect((await json(capped)).error).toBe("client_pending_cap");
    // approve a, nobody collects it -> full queue gives 503, signature survives
    await app.request(`/approve/${a.id}`, { method: "POST", headers: { "x-mandaterail-operator-attestation": await attest(app, "approve", a.id), "content-type": "application/json" }, body: JSON.stringify({ signature: "c2ln" }) });
    await app.request(`/reject/${b.id}`, { method: "POST", headers: { "x-mandaterail-operator-attestation": await attest(app, "reject", b.id) } });
    expect((await signReq()).status).toBe(503);
    expect(await has(a.id)).toBe(true);
    // requester collects a -> now evictable
    expect((await json(await st(app, a))).signature).toBe("c2ln");
    expect((await signReq()).status).toBe(202);
    expect(await has(a.id)).toBe(false);
    expect(await has(b.id)).toBe(true); // uncollected rejection kept
    expect((await st(app, a)).status).toBe(404);
  });

  it("per-client pending cap: one client cannot fill the queue", async () => {
    process.env.AC2_BRIDGE_MAX_PENDING = "10";
    process.env.AC2_BRIDGE_MAX_PENDING_PER_CLIENT = "2";
    process.env.OPERATOR_ATTESTATION_MODE = "token-lab";
    process.env.ALLOW_INSECURE_DEV = "1";
    process.env.AC2_OPERATOR_TOKEN = "lab-token";
    const { app } = make();
    const sign = (ip: string) => app.request("/sign", { method: "POST", headers: { "content-type": "application/json", "x-test-ip": ip, "x-mandaterail-operator-token": "lab-token" }, body: JSON.stringify({ message: "x" }) });
    expect((await sign("10.0.0.1")).status).toBe(202);
    expect((await sign("10.0.0.1")).status).toBe(202);
    const capped = await sign("10.0.0.1");
    expect(capped.status).toBe(429);
    expect((await json(capped)).error).toBe("client_pending_cap");
    expect((await sign("10.0.0.2")).status).toBe(202);
  });

  it("TTL: pending becomes expired, status reports it, approve is 409", async () => {
    process.env.AC2_BRIDGE_PENDING_TTL_MS = "60000";
    const clock = { t: 1_000_000 };
    const { app } = make(() => clock.t);
    const a = await queue(app);
    clock.t += 59_999;
    expect((await json(await st(app, a))).status).toBe("pending");
    clock.t += 1;
    expect(await json(await st(app, a))).toEqual({ id: a.id, status: "expired" });
    const ev = await attest(app, "approve", a.id);
    const res = await app.request(`/approve/${a.id}`, { method: "POST", headers: { "x-mandaterail-operator-attestation": ev, "content-type": "application/json" }, body: JSON.stringify({ signature: "c2ln" }) });
    expect(res.status).toBe(409);
  });

  it("retention: finalized items and their token hashes are evicted", async () => {
    process.env.AC2_BRIDGE_RETENTION_MS = "60000";
    const clock = { t: 5_000_000 };
    const { app, queueStore } = make(() => clock.t);
    const a = await queue(app);
    await app.request(`/approve/${a.id}`, { method: "POST", headers: { "x-mandaterail-operator-attestation": await attest(app, "approve", a.id), "content-type": "application/json" }, body: JSON.stringify({ signature: "c2ln" }) });
    clock.t += 59_000;
    expect((await json(await st(app, a))).status).toBe("approved");
    clock.t += 1_000;
    expect((await st(app, a)).status).toBe(404);
    expect(await queueStore.get(a.id, clock.t)).toBeNull();
  });

  it("POST /sign is rate limited (429)", async () => {
    process.env.AC2_BRIDGE_SIGN_RATE_PER_MIN = "3";
    process.env.AC2_BRIDGE_SIGN_RATE_PER_CLIENT = "2";
    const { app } = make();
    await queue(app);
    await queue(app);
    const res = await app.request("/sign", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ message: "x" }) });
    expect(res.status).toBe(429);
    expect((await json(res)).error).toBe("rate_limited");
  });

  it("OA-P2-M: unauthenticated non-loopback /sign is rejected by auth and does not consume quota", async () => {
    process.env.AC2_BRIDGE_SIGN_RATE_PER_MIN = "2";
    process.env.AC2_BRIDGE_SIGN_RATE_PER_CLIENT = "2";
    const { app } = make();
    for (let i = 0; i < 20; i++) {
      const r = await app.request("/sign", { method: "POST", headers: { "content-type": "application/json", "x-test-ip": "203.0.113.9" }, body: JSON.stringify({ message: "x" }) });
      expect(r.status).toBe(401);
    }
    // legit loopback agent still has its full quota (global 2)
    await queue(app);
    await queue(app);
  });

  it("gate: per-client sign rate / pending cap must be <= global", () => {
    process.env.AC2_BRIDGE_SIGN_RATE_PER_MIN = "5";
    process.env.AC2_BRIDGE_SIGN_RATE_PER_CLIENT = "6";
    expect(checkOperatorGate().ok).toBe(false);
    process.env.AC2_BRIDGE_SIGN_RATE_PER_CLIENT = "5";
    expect(checkOperatorGate().ok).toBe(true);
    process.env.AC2_BRIDGE_MAX_PENDING = "10";
    process.env.AC2_BRIDGE_MAX_PENDING_PER_CLIENT = "11";
    expect(checkOperatorGate().ok).toBe(false);
  });

  it("gate refuses out-of-range queue limits", () => {
    process.env.AC2_BRIDGE_MAX_PENDING = "0";
    expect(checkOperatorGate().ok).toBe(false);
    process.env.AC2_BRIDGE_MAX_PENDING = "10001";
    expect(checkOperatorGate().ok).toBe(false);
    delete process.env.AC2_BRIDGE_MAX_PENDING;
    process.env.AC2_BRIDGE_PENDING_TTL_MS = "1000";
    expect(checkOperatorGate().ok).toBe(false);
  });
});

describe("MainNet startup refusal (checkOperatorGate)", () => {
  it("refuses signed-challenge without OPERATOR_SIGNDATA_DOMAIN", () => {
    delete process.env.OPERATOR_SIGNDATA_DOMAIN;
    process.env.NETWORK = ALGORAND_MAINNET_CAIP2;
    process.env.ALLOW_MAINNET = "1";
    const r = checkOperatorGate({ bindHost: "127.0.0.1" });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/OPERATOR_SIGNDATA_DOMAIN/);
    process.env.OPERATOR_SIGNDATA_DOMAIN = "mandaterail.pages.dev";
    expect(checkOperatorGate({ bindHost: "127.0.0.1" }).ok).toBe(true);
  });
  it("refuses token-lab on MainNet even with a token and domain", () => {
    process.env.NETWORK = ALGORAND_MAINNET_CAIP2;
    process.env.OPERATOR_ATTESTATION_MODE = "token-lab";
    process.env.AC2_OPERATOR_TOKEN = "secret";
    process.env.OPERATOR_SIGNDATA_DOMAIN = "mandaterail.pages.dev";
    const r = checkOperatorGate();
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/token-lab/);
  });
});

const FWD: Array<[string, string]> = [
  ["x-forwarded-for", "198.51.100.7"],
  ["forwarded", "for=198.51.100.7"],
  ["cf-connecting-ip", "198.51.100.7"],
  ["x-real-ip", "198.51.100.7"],
  ["true-client-ip", "198.51.100.7"],
  ["x-forwarded-host", "bridge.example.com"],
  ["x-forwarded-proto", "https"],
  ["via", "1.1 proxy"],
  ["x-client-ip", "198.51.100.7"],
  ["fastly-client-ip", "198.51.100.7"],
];

describe("OA-P1-O forwarded/proxied requests on loopback are not local", () => {
  it("signed-challenge: POST /sign denied with any forwarding header", async () => {
    const { app } = make();
    for (const [h, v] of FWD) {
      const r = await app.request("/sign", { method: "POST", headers: { "content-type": "application/json", [h]: v }, body: JSON.stringify({ message: "x" }) });
      expect(r.status, h).toBe(401);
    }
    await queue(app); // plain loopback still works
  });

  it("signed-challenge: POST /sign denied when TRUSTED_PROXY_HOPS > 0 even without headers", async () => {
    process.env.AC2_BRIDGE_TRUSTED_PROXY_HOPS = "1";
    const { app } = make();
    const r = await app.request("/sign", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ message: "x" }) });
    expect(r.status).toBe(401);
  });

  it("tokenless token-lab: operator routes and requester status denied with forwarding headers", async () => {
    process.env.OPERATOR_ATTESTATION_MODE = "token-lab";
    process.env.ALLOW_INSECURE_DEV = "1";
    const { app } = make();
    const a = await queue(app); // plain loopback, tokenless lab
    for (const [h, v] of FWD) {
      expect((await app.request("/pending", { headers: { [h]: v } })).status, `pending ${h}`).toBe(401);
      expect((await app.request(`/approve/${a.id}`, { method: "POST", headers: { [h]: v, "content-type": "application/json" }, body: JSON.stringify({ signature: "c2ln" }) })).status, `approve ${h}`).toBe(401);
      expect((await app.request(`/reject/${a.id}`, { method: "POST", headers: { [h]: v } })).status, `reject ${h}`).toBe(401);
      expect((await app.request("/sign", { method: "POST", headers: { [h]: v, "content-type": "application/json" }, body: JSON.stringify({ message: "x" }) })).status, `sign ${h}`).toBe(401);
      expect((await app.request(`/requests/${a.id}/status`, { headers: { [h]: v } })).status, `status ${h}`).toBe(401);
    }
    // plain loopback lab still works; requester token still works through a proxy
    expect((await app.request("/pending")).status).toBe(200);
    expect((await app.request(`/requests/${a.id}/status`, { headers: { "x-forwarded-for": "198.51.100.7", [REQUESTER_TOKEN_HEADER]: a.requesterToken } })).status).toBe(200);
  });

  it("token-lab with AC2_OPERATOR_TOKEN: forwarded requests need the token", async () => {
    process.env.OPERATOR_ATTESTATION_MODE = "token-lab";
    process.env.AC2_OPERATOR_TOKEN = "lab-token";
    const { app } = make();
    expect((await app.request("/pending", { headers: { "cf-connecting-ip": "198.51.100.7" } })).status).toBe(401);
    expect((await app.request("/pending", { headers: { "cf-connecting-ip": "198.51.100.7", "x-mandaterail-operator-token": "lab-token" } })).status).toBe(200);
  });

  it("startup refusals with TRUSTED_PROXY_HOPS > 0", () => {
    process.env.AC2_BRIDGE_TRUSTED_PROXY_HOPS = "1";
    delete process.env.OPERATOR_SIGNDATA_DOMAIN;
    // signed-challenge on loopback bind: domain now required
    let r = checkOperatorGate({ bindHost: "127.0.0.1" });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/OPERATOR_SIGNDATA_DOMAIN/);
    process.env.OPERATOR_SIGNDATA_DOMAIN = "mandaterail.pages.dev";
    expect(checkOperatorGate({ bindHost: "127.0.0.1" }).ok).toBe(true);
    // tokenless token-lab refused
    process.env.OPERATOR_ATTESTATION_MODE = "token-lab";
    process.env.ALLOW_INSECURE_DEV = "1";
    r = checkOperatorGate({ bindHost: "127.0.0.1" });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/tokenless token-lab/);
    process.env.AC2_OPERATOR_TOKEN = "lab-token";
    expect(checkOperatorGate({ bindHost: "127.0.0.1" }).ok).toBe(true);
  });
});

describe("OA-P3-P loopback client key normalization", () => {
  it("127.0.0.0/8, ::1 and ::ffff:127.x share one /sign quota", async () => {
    process.env.AC2_BRIDGE_SIGN_RATE_PER_MIN = "10";
    process.env.AC2_BRIDGE_SIGN_RATE_PER_CLIENT = "3";
    const { app } = make();
    const sign = (ip: string) => app.request("/sign", { method: "POST", headers: { "content-type": "application/json", "x-test-ip": ip }, body: JSON.stringify({ message: "x" }) });
    expect((await sign("127.0.0.1")).status).toBe(202);
    expect((await sign("127.0.0.3")).status).toBe(202);
    expect((await sign("::1")).status).toBe(202);
    expect((await sign("::ffff:127.9.9.9")).status).toBe(429);
  });
});

describe("OA-P2-R auto-local signing only for trusted local callers", () => {
  it("POST /sign auto-local: 200 on direct loopback, 403 with any forwarding header or from non-loopback", async () => {
    process.env.OPERATOR_ATTESTATION_MODE = "token-lab";
    process.env.ALLOW_INSECURE_DEV = "1";
    process.env.AC2_BRIDGE_AUTO_LOCAL = "true";
    process.env.ALGORAND_MNEMONIC = algosdk.secretKeyToMnemonic(algosdk.generateAccount().sk);
    const { app } = make();
    const sign = (headers: Record<string, string>) => app.request("/sign", { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify({ message: "x" }) });
    const ok = await sign({});
    expect(ok.status).toBe(200);
    expect(typeof (await json(ok)).signature).toBe("string");
    for (const [h, v] of FWD) expect((await sign({ [h]: v })).status, h).toBe(403);
    expect((await sign({ "x-test-ip": "10.0.0.8" })).status).toBe(403);
  });

  it("POST /sign auto-local: 403 when TRUSTED_PROXY_HOPS > 0 (defense in depth; startup also refuses)", async () => {
    process.env.OPERATOR_ATTESTATION_MODE = "token-lab";
    process.env.ALLOW_INSECURE_DEV = "1";
    process.env.AC2_BRIDGE_AUTO_LOCAL = "true";
    process.env.AC2_BRIDGE_TRUSTED_PROXY_HOPS = "1";
    process.env.AC2_OPERATOR_TOKEN = "lab-token";
    process.env.ALGORAND_MNEMONIC = algosdk.secretKeyToMnemonic(algosdk.generateAccount().sk);
    expect(checkOperatorGate().ok).toBe(false);
    const { app } = make();
    const r = await app.request("/sign", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ message: "x" }) });
    expect(r.status).toBe(403);
  });
});

describe("T8 requester-key auth on POST /sign", () => {
  const rq = algosdk.generateAccount();
  const RQ = rq.addr.toString();
  const REMOTE = "203.0.113.5";

  async function signedSign(app: App, body: string, opts: { ip?: string; tamper?: string } = {}) {
    const ip = opts.ip ?? REMOTE;
    const chRes = await app.request(`/requester/challenge?address=${RQ}`, { headers: { "x-test-ip": ip } });
    expect(chRes.status).toBe(200);
    expect(chRes.headers.get("cache-control")).toBe("no-store");
    const ch = await json(chRes);
    const header = signRequesterRequest({ sk: rq.sk, address: RQ, nonce: ch.nonce, audience: ch.audience, body });
    const res = await app.request("/sign", {
      method: "POST",
      headers: { "content-type": "application/json", "x-test-ip": ip, "x-mandaterail-requester-auth": header },
      body: opts.tamper ?? body,
    });
    return { res, header };
  }

  it("allowlisted key can queue from a non-loopback address; replay and tampering refused", async () => {
    process.env.REQUESTER_ALLOWLIST = RQ;
    const { app } = make();
    const body = JSON.stringify({ message: "hello", mandateId: "m-1" });
    const { res, header } = await signedSign(app, body);
    expect(res.status).toBe(202);
    const q = await json(res);
    const replay = await app.request("/sign", {
      method: "POST",
      headers: { "content-type": "application/json", "x-test-ip": REMOTE, "x-mandaterail-requester-auth": header },
      body,
    });
    expect(replay.status).toBe(401);
    expect((await json(replay)).error).toBe("replayed_nonce");
    const t = await signedSign(app, body, { tamper: JSON.stringify({ message: "evil", mandateId: "m-1" }) });
    expect(t.res.status).toBe(401);
    expect((await json(t.res)).error).toBe("requester_auth_failed");
    // requester token flow unchanged
    const st = await app.request(`/requests/${q.id}/status`, { headers: { [REQUESTER_TOKEN_HEADER]: q.requesterToken, "x-test-ip": REMOTE } });
    expect((await json(st)).status).toBe("pending");
    // queued item is attributed to the requester key, visible to the operator
    const list = await app.request("/pending", { headers: { "x-mandaterail-operator-attestation": await attest(app, "list", "pending") } });
    expect(JSON.stringify(await json(list))).toContain(q.id);
  });

  it("non-allowlisted key refused even from loopback when it presents the header", async () => {
    process.env.REQUESTER_ALLOWLIST = algosdk.generateAccount().addr.toString();
    const { app } = make();
    const { res } = await signedSign(app, JSON.stringify({ message: "x" }), { ip: "127.0.0.1" });
    expect(res.status).toBe(401);
    expect((await json(res)).error).toBe("requester_auth_failed"); // generic: no allowlist oracle
  });

  it("hashes raw body bytes: semantically equal JSON with other bytes is refused", async () => {
    process.env.REQUESTER_ALLOWLIST = RQ;
    const { app } = make();
    const body = '{"message":"hi"}';
    const t = await signedSign(app, body, { tamper: '{ "message": "hi" }' });
    expect(t.res.status).toBe(401);
    // non-UTF-8 bytes are rejected as a malformed request
    const bad = await app.request("/sign", { method: "POST", headers: { "x-test-ip": "127.0.0.1" }, body: new Uint8Array([0x7b, 0xff, 0x7d]) });
    expect(bad.status).toBe(400);
  });

  it("TestNet loopback behaviour unchanged without the header (T9 removes it)", async () => {
    process.env.REQUESTER_ALLOWLIST = RQ;
    const { app } = make();
    await queue(app);
    const remote = await app.request("/sign", { method: "POST", headers: { "content-type": "application/json", "x-test-ip": REMOTE }, body: JSON.stringify({ message: "x" }) });
    expect(remote.status).toBe(401);
  });

  it("MainNet profile: loopback alone is not enough for /sign", async () => {
    process.env.NETWORK = ALGORAND_MAINNET_CAIP2;
    process.env.REQUESTER_ALLOWLIST = RQ;
    const { app } = make();
    const res = await app.request("/sign", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ message: "x" }) });
    expect(res.status).toBe(401);
    expect((await json(res)).error).toBe("requester_auth_required");
    const ok = await signedSign(app, JSON.stringify({ message: "x" }), { ip: "127.0.0.1" });
    expect(ok.res.status).toBe(202);
  });

  it("T9: MainNet — remote and loopback callers both need a requester key; SDK + ac2-client sign end to end", async () => {
    process.env.NETWORK = ALGORAND_MAINNET_CAIP2;
    process.env.ALLOW_MAINNET = "1";
    process.env.REQUESTER_ALLOWLIST = RQ;
    const { app } = make();
    const viaApp = (ip: string) =>
      (async (url: string | URL, init?: RequestInit) => {
        const u = new URL(String(url));
        return app.request(u.pathname + u.search, { ...init, headers: { ...(init?.headers as Record<string, string>), "x-test-ip": ip } });
      }) as unknown as typeof fetch;
    // no requester key: refused for loopback and remote alike
    for (const ip of ["127.0.0.1", "::1", "203.0.113.9"]) {
      const bare = new Ac2BridgeClient({ baseUrl: "http://bridge", fetch: viaApp(ip) });
      await expect(bare.sign({ type: "IntentMandate/v1", sig_hint: "raw-ed25519", message: "x" } as never)).rejects.toMatchObject({ status: 401 });
    }
    // operator list via loopback (token-lab trust) is not available on MainNet
    expect((await app.request("/pending", { headers: { "x-test-ip": "127.0.0.1" } })).status).toBeGreaterThanOrEqual(401);
    const sdk = new Ac2BridgeClient({
      baseUrl: "http://bridge",
      fetch: viaApp("203.0.113.9"),
      requester: { address: RQ, signBytes: (b) => algosdk.signBytes(b, rq.sk) },
    });
    const r = (await sdk.sign({ type: "IntentMandate/v1", sig_hint: "raw-ed25519", message: "hello" } as never)) as { id: string; requesterToken: string };
    expect(r.id).toBeTruthy();
    expect((await sdk.requestStatus(r.id, r.requesterToken)).status).toBe("pending");
    const wrongKey = algosdk.generateAccount();
    const forged = new Ac2BridgeClient({ baseUrl: "http://bridge", fetch: viaApp("203.0.113.9"), requester: { address: RQ, signBytes: (b) => algosdk.signBytes(b, wrongKey.sk) } });
    await expect(forged.sign({ type: "IntentMandate/v1", sig_hint: "raw-ed25519", message: "x" } as never)).rejects.toMatchObject({ status: 401 });
    // ac2-client signer: gets queued (202) then times out waiting for an operator
    const signer = new HttpAc2BridgeSigner({ baseUrl: "http://bridge", fetch: viaApp("203.0.113.9"), requester: { address: RQ, sk: rq.sk }, timeoutMs: 50, pollIntervalMs: 10 });
    await expect(signer.signIntentMandate({ id: "m-1", principal: RQ } as never)).rejects.toThrow(/timed out waiting for approval|aborted/) // queued, i.e. /sign accepted the requester key;
  });

  it("/requester/challenge: 404 when no allowlist, 400 on bad address, no allowlist oracle", async () => {
    const { app } = make();
    expect((await app.request(`/requester/challenge?address=${RQ}`)).status).toBe(404);
    process.env.REQUESTER_ALLOWLIST = RQ;
    const { app: app2 } = make();
    expect((await app2.request("/requester/challenge?address=nope")).status).toBe(400);
    const stranger = algosdk.generateAccount().addr.toString();
    expect((await app2.request(`/requester/challenge?address=${stranger}`)).status).toBe(200);
  });
});

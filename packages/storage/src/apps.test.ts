/**
 * App-level shared state: two ac2-bridge instances and two console instances
 * on the same Postgres (+ Redis) behave as one service — a challenge issued by
 * one instance is accepted once by another, never twice; the bridge queue and
 * console mandates are shared. Skipped without MR_TEST_PG_URL.
 */
import { afterAll, afterEach, beforeEach, describe, expect, it } from "vitest";
import algosdk from "algosdk";
import { encodeAttestationHeader, signMandate, CHALLENGE_RATE_WINDOW_MS } from "@mandaterail/core";
import { PgChallengeStore, PgMandateStore, PgQueueStore, PgRateLimitStore } from "./pg.js";
import { RedisChallengeStore, RedisRateLimitStore } from "./redis.js";
import { closeShared, getPool, getRedis, PG_URL, REDIS_URL, uid } from "./test-helpers.js";

const BRIDGE = "../../../apps/ac2-bridge/src/app.js";
const CONSOLE = "../../../apps/console/src/app.js";
const op = algosdk.generateAccount();
const ATT = "x-mandaterail-operator-attestation";
const KEYS = ["NETWORK", "OPERATOR_ATTESTATION_MODE", "OPERATOR_ALLOWLIST", "OPERATOR_SIGNDATA_DOMAIN", "CONSOLE_DATA_DIR", "AC2_BRIDGE_AUTO_LOCAL", "ALLOW_INSECURE_DEV"];
const saved: Record<string, string | undefined> = {};
beforeEach(() => {
  for (const k of KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
  process.env.NETWORK = "algorand:SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=";
  process.env.OPERATOR_ATTESTATION_MODE = "signed-challenge";
  process.env.OPERATOR_ALLOWLIST = op.addr.toString();
  process.env.OPERATOR_SIGNDATA_DOMAIN = "mandaterail.pages.dev";
});
afterEach(() => { for (const k of KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; } });
afterAll(closeShared);

type AnyApp = { request: (p: string, i?: RequestInit) => Promise<Response> };
const json = async (r: Response) => (await r.json()) as any;
async function attest(app: AnyApp, action: string, id: string): Promise<string> {
  const ch = await json(await app.request(`/operator/challenge?action=${action}&id=${encodeURIComponent(id)}`));
  const sig = algosdk.signBytes(new TextEncoder().encode(ch.message), op.sk);
  return encodeAttestationHeader({ nonce: ch.nonce, address: op.addr.toString(), format: "algosdk", signature: Buffer.from(sig).toString("base64") });
}

describe.skipIf(!PG_URL)("two app instances on shared Postgres/Redis", () => {
  it("ac2-bridge: challenge + queue shared across instances, nonce single-use across them", async () => {
    const pool = await getPool();
    const useRedis = Boolean(REDIS_URL);
    const audience = uid("mandaterail-ac2-bridge");
    const queue = uid("bridge");
    const limits = { maxPending: 1000, pendingTtlMs: 900_000, retentionMs: 600_000, maxPendingPerClient: 50 };
    const stores = () => ({
      challenges: useRedis ? new RedisChallengeStore(getRedis(), { audience }) : new PgChallengeStore(pool, { audience }),
      challengeLimiter: useRedis
        ? new RedisRateLimitStore(getRedis(), { name: uid("crl"), windowMs: CHALLENGE_RATE_WINDOW_MS, perKey: 30, global: 600 })
        : new PgRateLimitStore(pool, { name: uid("crl"), windowMs: CHALLENGE_RATE_WINDOW_MS, perKey: 30, global: 600 }),
      signLimiter: new PgRateLimitStore(pool, { name: uid("srl"), windowMs: 60_000, perKey: 10, global: 60 }),
      queue: new PgQueueStore(pool, { queue, limits }),
    });
    const { createBridgeApp } = (await import(BRIDGE)) as { createBridgeApp: (o: object) => { app: AnyApp } };
    const A = createBridgeApp({ remoteAddress: () => "127.0.0.1", stores: stores() }).app;
    const B = createBridgeApp({ remoteAddress: () => "127.0.0.1", stores: stores() }).app;

    const signed = await A.request("/sign", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ message: "hello", mandateId: "m-1" }) });
    expect(signed.status).toBe(202);
    const { id, requesterToken } = await json(signed);

    // challenge from A, used at B
    const att = await attest(A, "approve", id);
    const ok = await B.request(`/approve/${id}`, { method: "POST", headers: { "content-type": "application/json", [ATT]: att }, body: JSON.stringify({ signature: "c2ln", address: "ADDR" }) });
    expect(ok.status).toBe(200);
    // replay of the same evidence at A: rejected
    const replay = await A.request(`/reject/${id}`, { method: "POST", headers: { [ATT]: att } });
    expect(replay.status).toBe(401);
    expect((await json(replay)).error).toBe("replayed_nonce");
    // second finalize through A with fresh evidence: 409 (shared state)
    const again = await A.request(`/reject/${id}`, { method: "POST", headers: { [ATT]: await attest(B, "reject", id) } });
    expect(again.status).toBe(409);
    // requester reads the result from the other instance
    const st = await A.request(`/requests/${id}/status`, { headers: { "x-mandaterail-requester-token": requesterToken } });
    expect(await json(st)).toMatchObject({ id, status: "approved", signature: "c2ln" });
    // B lists it
    const list = await B.request("/pending", { headers: { [ATT]: await attest(A, "list", "pending") } });
    expect((await json(list)).pending.map((p: any) => p.id)).toContain(id);
  });

  it("console: signed mandate created on A, authorize-check on B; verified flag shared", async () => {
    const pool = await getPool();
    const audience = uid("mandaterail-console");
    const store = uid("console");
    const stores = () => ({
      challenges: new PgChallengeStore(pool, { audience }),
      limiter: new PgRateLimitStore(pool, { name: uid("conrl"), windowMs: 60_000, perKey: 30, global: 300 }),
      mandates: new PgMandateStore(pool, { store }),
    });
    const { createConsoleApp } = (await import(CONSOLE)) as { createConsoleApp: (o: object) => { app: AnyApp } };
    const A = createConsoleApp({ remoteAddress: () => "127.0.0.1", stores: stores() }).app;
    const B = createConsoleApp({ remoteAddress: () => "127.0.0.1", stores: stores() }).app;

    const principal = algosdk.generateAccount();
    const base = {
      id: "m-shared", principal: principal.addr.toString(), agent: "did:example:agent-1", maxAmount: "5.00", asset: "USDC",
      allowlist: ["demo-merchant"], expiresAt: new Date(Date.now() + 3600_000).toISOString(), revoked: false,
      nonce: "n-shared", createdAt: new Date().toISOString(),
    };
    const body = { ...base, signature: signMandate(base as any, principal.sk) };
    const created = await A.request("/mandates", { method: "POST", headers: { "content-type": "application/json", [ATT]: await attest(B, "mandate.create", "m-shared") }, body: JSON.stringify(body) });
    expect(created.status).toBe(201);
    const read = await B.request("/mandates/m-shared", { headers: { [ATT]: await attest(A, "mandate.read", "m-shared") } });
    expect((await json(read)).authorization.status).toBe("signature-verified");
    const chk = await B.request("/mandates/m-shared/authorize-check", { method: "POST", headers: { "content-type": "application/json", [ATT]: await attest(B, "mandate.read", "m-shared") }, body: JSON.stringify({ merchantId: "demo-merchant", amount: "5.00", asset: "USDC" }) });
    expect(chk.status).toBe(200);
    const dup = await B.request("/mandates", { method: "POST", headers: { "content-type": "application/json", [ATT]: await attest(A, "mandate.create", "m-shared") }, body: JSON.stringify(body) });
    expect(dup.status).toBe(409);
    const rev = await B.request("/mandates/m-shared/revoke", { method: "POST", headers: { [ATT]: await attest(A, "mandate.revoke", "m-shared") } });
    expect((await json(rev)).revoked).toBe(true);
    const after = await A.request("/mandates/m-shared/authorize-check", { method: "POST", headers: { [ATT]: await attest(A, "mandate.read", "m-shared") } });
    expect(after.status).toBe(403);
  });
});

describe.skipIf(!PG_URL)("T6: apps built from openStateBackend() share state", () => {
  it("bridge x2 + console via `backend` option", async () => {
    await getPool();
    const { openStateBackend } = await import("./backend.js");
    const env = { STATE_BACKEND: REDIS_URL ? "redis+postgres" : "postgres", DATABASE_URL: PG_URL, REDIS_URL };
    const b1 = (await openStateBackend(env, { mainnet: false }))!;
    const b2 = (await openStateBackend(env, { mainnet: false }))!;
    try {
      process.env.OPERATOR_CHALLENGE_AUDIENCE = uid("aud");
      const { createBridgeApp } = (await import(BRIDGE)) as { createBridgeApp: (o: object) => { app: AnyApp } };
      const A = createBridgeApp({ remoteAddress: () => "127.0.0.1", backend: b1 }).app;
      const B = createBridgeApp({ remoteAddress: () => "127.0.0.1", backend: b2 }).app;
      const signed = await A.request("/sign", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ message: "hi" }) });
      expect(signed.status).toBe(202);
      const { id } = await json(signed);
      const att = await attest(A, "approve", id);
      const ok = await B.request(`/approve/${id}`, { method: "POST", headers: { "content-type": "application/json", [ATT]: att }, body: JSON.stringify({ signature: "c2ln" }) });
      expect(ok.status).toBe(200);
      expect((await A.request(`/reject/${id}`, { method: "POST", headers: { [ATT]: att } })).status).toBe(401);
    } finally {
      delete process.env.OPERATOR_CHALLENGE_AUDIENCE;
      await b1.close();
      await b2.close();
    }
  });
});

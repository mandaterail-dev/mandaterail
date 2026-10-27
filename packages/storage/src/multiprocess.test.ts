/**
 * Restart and multi-process tests against real Postgres / Redis
 * (run via scripts/with-state-services.sh; skipped without MR_TEST_*).
 */
import { afterAll, describe, expect, it } from "vitest";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { promisify } from "node:util";
import { Redis } from "ioredis";
import type { IntentMandate } from "@mandaterail/schema";
import { migratePostgres, PgChallengeStore, PgMandateStore, PgQueueStore, PgRateLimitStore } from "./pg.js";
import { RedisChallengeStore, RedisRateLimitStore } from "./redis.js";
import { closeShared, getPool, newPool, newRedis, PG_URL, REDIS_URL, uid } from "./test-helpers.js";

const run = promisify(execFile);
const here = path.dirname(fileURLToPath(import.meta.url));
const TSX = path.resolve(here, "../node_modules/.bin/tsx");
const WORKER = path.resolve(here, "mp-worker.ts");

async function race(jobs: object[]): Promise<any[]> {
  const startAt = Date.now() + 2500;
  const outs = await Promise.all(
    jobs.map((j) => run(TSX, [WORKER, JSON.stringify({ ...j, startAt })], { env: process.env, timeout: 30_000 })),
  );
  return outs.map((o) => JSON.parse(o.stdout.trim().split("\n").pop()!));
}

afterAll(closeShared);
const both = [...(PG_URL ? ["postgres" as const] : []), ...(REDIS_URL && PG_URL ? ["redis" as const] : [])];
const lim = { maxPending: 100, pendingTtlMs: 600_000, retentionMs: 600_000, maxPendingPerClient: 100 };

describe.skipIf(!PG_URL)("restart: state survives a new process/connection", () => {
  for (const b of both) {
    it(`[${b}] nonce issued before restart is consumable once after it; limiter counts persist`, async () => {
      const audience = uid("aud");
      const name = uid("rl");
      // "process 1"
      const p1 = newPool();
      const r1 = b === "redis" ? newRedis() : undefined;
      const s1 = b === "redis" ? new RedisChallengeStore(r1!, { audience }) : new PgChallengeStore(p1, { audience });
      const l1 = b === "redis"
        ? new RedisRateLimitStore(r1!, { name, windowMs: 60_000, perKey: 2, global: 10 })
        : new PgRateLimitStore(p1, { name, windowMs: 60_000, perKey: 2, global: 10 });
      if (b === "postgres") await migratePostgres(p1, { network: "testnet", verifyNetwork: async (p) => ({ genesisHash: p.caip2.slice(9) }) });
      const ch = await s1.issue("approve", "req-1");
      const used = await s1.issue("approve", "req-2");
      expect((await s1.consume(used.nonce)).ok).toBe(true);
      expect(await l1.take("ip")).toBe(true);
      expect(await l1.take("ip")).toBe(true);
      await p1.end();
      r1?.disconnect();
      // "process 2" after restart
      const p2 = newPool();
      const r2 = b === "redis" ? newRedis() : undefined;
      const s2 = b === "redis" ? new RedisChallengeStore(r2!, { audience }) : new PgChallengeStore(p2, { audience });
      const l2 = b === "redis"
        ? new RedisRateLimitStore(r2!, { name, windowMs: 60_000, perKey: 2, global: 10 })
        : new PgRateLimitStore(p2, { name, windowMs: 60_000, perKey: 2, global: 10 });
      expect(await s2.consume(used.nonce)).toEqual({ ok: false, error: "replayed_nonce" });
      expect((await s2.consume(ch.nonce)).ok).toBe(true);
      expect(await s2.consume(ch.nonce)).toEqual({ ok: false, error: "replayed_nonce" });
      expect(await l2.take("ip")).toBe(false);
      await p2.end();
      r2?.disconnect();
    });
  }

  it("[postgres] queue items (incl. token hash) and mandates (incl. verified flag) survive", async () => {
    const queue = uid("q");
    const store = uid("m");
    const p1 = newPool();
    const now = Date.now();
    await new PgQueueStore(p1, { queue, limits: lim }).insert(
      {
        id: "a",
        status: "pending",
        createdAt: new Date(now).toISOString(),
        createdMs: now,
        clientKey: "k",
        request: { message: "hello", mandateId: "m-1" },
        requesterTokenHash: createHash("sha256").update("tok").digest(),
      },
      now,
    );
    await new PgMandateStore(p1, { store }).create(
      {
        id: "m-1",
        principal: "did:example:alice",
        agent: "did:example:agent-1",
        maxAmount: "1.00",
        asset: "USDC",
        allowlist: ["m"],
        expiresAt: new Date(now + 3600_000).toISOString(),
        revoked: false,
        nonce: "n",
        signature: null,
        createdAt: new Date(now).toISOString(),
      } as IntentMandate,
      { signatureVerified: true },
    );
    await p1.end();

    const p2 = newPool();
    const q2 = new PgQueueStore<{ message: string }>(p2, { queue, limits: lim });
    const it2 = await q2.get("a", Date.now());
    expect(it2?.request.message).toBe("hello");
    expect(it2?.requesterTokenHash.equals(createHash("sha256").update("tok").digest())).toBe(true);
    expect((await q2.finalize("a", "approved", { signature: "s" }, Date.now())).ok).toBe(true);
    const m2 = await new PgMandateStore(p2, { store }).get("m-1");
    expect(m2?.server.signatureVerified).toBe(true);
    await p2.end();
  });
});

describe.skipIf(!PG_URL)("multi-process races (separate Node processes)", () => {
  for (const b of both) {
    it(`[${b}] 6 processes consume one nonce: exactly one ok`, async () => {
      const audience = uid("mp");
      const rc = b === "redis" ? newRedis() : undefined;
      const s = rc ? new RedisChallengeStore(rc, { audience }) : new PgChallengeStore(await getPool(), { audience });
      const ch = await s.issue("approve", "req-x");
      rc?.disconnect();
      const rs = await race(Array.from({ length: 6 }, () => ({ op: "consume", backend: b, audience, nonce: ch.nonce })));
      expect(rs.filter((r) => r.ok)).toHaveLength(1);
      expect(rs.filter((r) => r.error === "replayed_nonce")).toHaveLength(5);
    }, 60_000);

    it(`[${b}] 4 processes × 15 takes, global 12: exactly 12 admitted`, async () => {
      const name = uid("mprl");
      const rs = await race(Array.from({ length: 4 }, () => ({ op: "take", backend: b, name, global: 12, perKey: 100, n: 15 })));
      expect(rs.reduce((a, r) => a + r.admitted, 0)).toBe(12);
    }, 60_000);
  }

  it("[postgres] 4 processes create 10 mandates each, cap 15: exactly 15 stored", async () => {
    const store = uid("mpm");
    await getPool();
    const rs = await race(
      Array.from({ length: 4 }, (_, p) => ({ op: "create", store, max: 15, ids: Array.from({ length: 10 }, (_, i) => `p${p}-${i}`) })),
    );
    expect(rs.reduce((a, r) => a + r.created, 0)).toBe(15);
    expect(await new PgMandateStore(await getPool(), { store }).list()).toHaveLength(15);
  }, 60_000);

  it("[postgres] 4 processes approve/reject one queue item: exactly one wins", async () => {
    const queue = uid("mpq");
    const now = Date.now();
    await new PgQueueStore(await getPool(), { queue, limits: lim }).insert(
      {
        id: "x",
        status: "pending",
        createdAt: new Date(now).toISOString(),
        createdMs: now,
        clientKey: "k",
        request: { message: "m" },
        requesterTokenHash: createHash("sha256").update("t").digest(),
      },
      now,
    );
    const rs = await race(
      Array.from({ length: 4 }, (_, i) => ({ op: "finalize", queue, id: "x", status: i % 2 ? "approved" : "rejected" })),
    );
    expect(rs.filter((r) => r.ok)).toHaveLength(1);
  }, 60_000);
});

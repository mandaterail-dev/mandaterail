/**
 * R19-P3-5: test-only shared-state wiring for app test suites (ac2-bridge,
 * console). When MR_TEST_PG_URL is set (scripts/with-state-services.sh), the
 * apps' tests run against real Postgres (+ Redis when MR_TEST_REDIS_URL is
 * set) instead of in-memory stores. Each factory call gets its own namespace
 * (queue / mandate store / limiter names) so tests stay independent.
 * Never used by production code.
 */
import { randomBytes } from "node:crypto";
import pg from "pg";
import { Redis } from "ioredis";
import type { StoreFactory } from "@mandaterail/core";
import { migratePostgres, PgChallengeStore, PgMandateStore, PgQueueStore, PgRateLimitStore } from "./pg.js";
import { RedisChallengeStore, RedisRateLimitStore } from "./redis.js";

let pool: pg.Pool | undefined;
let redis: Redis | undefined;

export const stateTestBackendKind = (): "memory" | "postgres" | "redis+postgres" =>
  !process.env.MR_TEST_PG_URL ? "memory" : process.env.MR_TEST_REDIS_URL ? "redis+postgres" : "postgres";

/** Call in beforeAll: connects and migrates (no-op without MR_TEST_PG_URL). */
export async function prepareStateTestBackend(): Promise<void> {
  if (!process.env.MR_TEST_PG_URL) return;
  if (!pool) {
    pool = new pg.Pool({ connectionString: process.env.MR_TEST_PG_URL, max: 10 });
    pool.on("error", () => undefined);
    await migratePostgres(pool, { network: "testnet", verifyNetwork: async (p) => ({ genesisHash: p.caip2.slice(9) }) });
  }
  if (process.env.MR_TEST_REDIS_URL && !redis) {
    redis = new Redis(process.env.MR_TEST_REDIS_URL, { maxRetriesPerRequest: 2 });
    redis.on("error", () => undefined);
  }
}

/** A fresh namespaced StoreFactory, or undefined when running memory-only. */
export function stateTestBackend(): StoreFactory | undefined {
  if (!process.env.MR_TEST_PG_URL) return undefined;
  if (!pool) throw new Error("call prepareStateTestBackend() in beforeAll first");
  const p = pool;
  const r = redis;
  const ns = `t${randomBytes(5).toString("hex")}`;
  return {
    challengeStore: (o) => (r ? new RedisChallengeStore(r, { ...o, audience: o.audience }) : new PgChallengeStore(p, o)),
    rateLimiter: (o) => (r ? new RedisRateLimitStore(r, { ...o, name: `${ns}:${o.name}` }) : new PgRateLimitStore(p, { ...o, name: `${ns}:${o.name}` })),
    queue: (name, limits) => new PgQueueStore(p, { queue: `${ns}:${name}`, limits }),
    mandates: (store = "console") => new PgMandateStore(p, { store: `${ns}:${store}` }),
  };
}

export async function closeStateTestBackend(): Promise<void> {
  redis?.disconnect();
  redis = undefined;
  await pool?.end();
  pool = undefined;
}

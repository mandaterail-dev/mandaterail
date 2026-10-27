/** Shared test wiring: in-memory always; Postgres / Redis when MR_TEST_* is set. */
import { randomBytes } from "node:crypto";
import pg from "pg";
import { Redis } from "ioredis";
import {
  InMemoryQueueStore,
  OperatorChallengeStore,
  RollingWindowRateLimiter,
  type ChallengeStore,
  type QueueLimits,
  type QueueStore,
  type RateLimitStore,
} from "@mandaterail/core";
import { migratePostgres, PgChallengeStore, PgQueueStore, PgRateLimitStore } from "./pg.js";
import { RedisChallengeStore, RedisRateLimitStore } from "./redis.js";

export const PG_URL = process.env.MR_TEST_PG_URL;
export const REDIS_URL = process.env.MR_TEST_REDIS_URL;
export const uid = (p: string) => `${p}-${randomBytes(5).toString("hex")}`;

export type Clock = { t: number; now: () => number };
export const clock = (t = 1_760_000_000_000): Clock => {
  const c = { t, now: () => c.t };
  return c;
};

/**
 * R18-P3-1: every test client gets an error listener, so a server restart
 * (or teardown) never surfaces as an unhandled 'error' event / non-zero exit.
 * Errors are swallowed here; assertions see failures through rejected calls.
 */
export function quiet<T extends { on(ev: "error", fn: (e: Error) => void): unknown }>(c: T): T {
  c.on("error", () => undefined);
  return c;
}
export function newRedis(): Redis {
  return quiet(new Redis(REDIS_URL!, { maxRetriesPerRequest: 2 }));
}

let pool: pg.Pool | undefined;
let redis: Redis | undefined;
export async function getPool(): Promise<pg.Pool> {
  if (!pool) {
    pool = quiet(new pg.Pool({ connectionString: PG_URL, max: 20 }));
    await migratePostgres(pool, { network: "testnet", verifyNetwork: async (p) => ({ genesisHash: p.caip2.slice(9) }) });
    await seedTestProviders(pool);
  }
  return pool;
}

/**
 * R25-P2-1: test-only provider allowlist rows (superuser connection): the
 * example hosts the release tests use, each pair under different operators.
 * The real seed (nodely only) comes from the migration.
 */
export const TEST_PROVIDERS: ReadonlyArray<{ host: string; operator: string }> = [
  { host: "idx-a.example", operator: "test-op-a" }, { host: "algod-a.example", operator: "test-op-a" },
  { host: "idx-b.example", operator: "test-op-b" }, { host: "algod-b.example", operator: "test-op-b" },
  { host: "idx-c.example", operator: "test-op-c" },
];
export async function seedTestProviders(p: pg.Pool | pg.PoolClient): Promise<void> {
  for (const n of ["testnet", "mainnet"]) {
    for (const e of TEST_PROVIDERS) {
      await p.query("INSERT INTO mr_network_provider (network, host, operator_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING", [n, e.host, e.operator]);
      // v11: the attestation's operators must also be pinned in mr_signer_operator
      await p.query(`DO $$ BEGIN IF to_regclass('mr_signer_operator') IS NOT NULL THEN
        INSERT INTO mr_signer_operator (network, operator) VALUES ('${n}', '${e.operator}') ON CONFLICT DO NOTHING; END IF; END $$`);
    }
  }
}
export function newPool(): pg.Pool {
  return quiet(new pg.Pool({ connectionString: PG_URL, max: 10 }));
}
export function getRedis(): Redis {
  if (!redis) redis = quiet(new Redis(REDIS_URL!, { lazyConnect: false, maxRetriesPerRequest: 2 }));
  return redis;
}
export async function closeShared(): Promise<void> {
  await pool?.end();
  pool = undefined;
  redis?.disconnect();
  redis = undefined;
}

export type Backend = "memory" | "postgres" | "redis";
export const backends = (): Backend[] =>
  ["memory", ...(PG_URL ? (["postgres"] as const) : []), ...(REDIS_URL ? (["redis"] as const) : [])];

export async function challengeStore(
  b: Backend,
  o: { audience: string; ttlMs?: number; maxEntries?: number; now?: () => number },
): Promise<ChallengeStore> {
  if (b === "postgres") return new PgChallengeStore(await getPool(), o);
  if (b === "redis") return new RedisChallengeStore(getRedis(), o);
  return new OperatorChallengeStore(o);
}

export async function rateLimiter(
  b: Backend,
  o: { name: string; windowMs: number; perKey: number; global: number; now?: () => number },
): Promise<RateLimitStore> {
  if (b === "postgres") return new PgRateLimitStore(await getPool(), o);
  if (b === "redis") return new RedisRateLimitStore(getRedis(), o);
  return new RollingWindowRateLimiter(o);
}

export async function queueStore<R>(b: "memory" | "postgres", limits: QueueLimits): Promise<QueueStore<R>> {
  if (b === "postgres") return new PgQueueStore<R>(await getPool(), { queue: uid("q"), limits });
  return new InMemoryQueueStore<R>(limits);
}

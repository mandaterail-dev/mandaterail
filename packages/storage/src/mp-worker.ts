/**
 * Multi-process test worker: its own pg pool / redis client, waits for a
 * shared start time, runs one racing operation, prints JSON on stdout.
 * Usage: tsx mp-worker.ts '<json>' (see multiprocess.test.ts).
 */
import pg from "pg";
import { Redis } from "ioredis";
import { PgChallengeStore, PgMandateStore, PgQueueStore, PgRateLimitStore, PgSpendStore } from "./pg.js";
import { RedisChallengeStore, RedisRateLimitStore } from "./redis.js";

type Job =
  | { op: "consume"; backend: "postgres" | "redis"; audience: string; nonce: string; startAt: number }
  | { op: "take"; backend: "postgres" | "redis"; name: string; global: number; perKey: number; n: number; startAt: number }
  | { op: "create"; store: string; ids: string[]; max: number; startAt: number }
  | { op: "finalize"; queue: string; id: string; status: "approved" | "rejected"; startAt: number }
  | { op: "reserve"; store: string; payer: string; n: number; amountMicro: string; perDayMicro: string; startAt: number };

const job = JSON.parse(process.argv[2]!) as Job;
const pool = new pg.Pool({ connectionString: process.env.MR_TEST_PG_URL, max: 4 });
pool.on("error", () => undefined);
const redis = "backend" in job && job.backend === "redis" ? new Redis(process.env.MR_TEST_REDIS_URL!) : undefined;
redis?.on("error", () => undefined);

async function main(): Promise<unknown> {
  // warm the connections before the start line
  await pool.query("SELECT 1");
  if (redis) await redis.ping();
  while (Date.now() < job.startAt) await new Promise((r) => setTimeout(r, 1));
  switch (job.op) {
    case "consume": {
      const s = job.backend === "redis"
        ? new RedisChallengeStore(redis!, { audience: job.audience })
        : new PgChallengeStore(pool, { audience: job.audience });
      return s.consume(job.nonce);
    }
    case "take": {
      const o = { name: job.name, windowMs: 60_000, perKey: job.perKey, global: job.global };
      const l = job.backend === "redis" ? new RedisRateLimitStore(redis!, o) : new PgRateLimitStore(pool, o);
      const rs = await Promise.all(Array.from({ length: job.n }, (_, i) => l.take(`k${process.pid}-${i % 3}`)));
      return { admitted: rs.filter(Boolean).length };
    }
    case "create": {
      const s = new PgMandateStore(pool, { store: job.store });
      const rs = await Promise.allSettled(
        job.ids.map((id) =>
          s.create(
            {
              id,
              principal: "did:example:alice",
              agent: "did:example:agent-1",
              maxAmount: "1.00",
              asset: "USDC",
              allowlist: ["m"],
              expiresAt: new Date(Date.now() + 3600_000).toISOString(),
              revoked: false,
              nonce: id,
              signature: null,
              createdAt: new Date().toISOString(),
            } as never,
            { maxMandates: job.max },
          ),
        ),
      );
      return { created: rs.filter((r) => r.status === "fulfilled").length };
    }
    case "reserve": {
      const s = new PgSpendStore(pool, { store: job.store });
      const caps = { perPaymentMicro: BigInt(job.amountMicro), perDayMicro: BigInt(job.perDayMicro) };
      const rs = await Promise.all(
        Array.from({ length: job.n }, (_, i) =>
          s.reserve({ id: `${process.pid}-${i}`, payer: job.payer, amountMicro: BigInt(job.amountMicro), caps, nowMs: Date.now() }),
        ),
      );
      return { reserved: rs.filter((r) => r.ok).length };
    }
    case "finalize": {
      const q = new PgQueueStore(pool, {
        queue: job.queue,
        limits: { maxPending: 100, pendingTtlMs: 600_000, retentionMs: 600_000, maxPendingPerClient: 100 },
      });
      const r = await q.finalize(job.id, job.status, { signature: `sig-${process.pid}` }, Date.now());
      return { ok: r.ok };
    }
  }
}

main()
  .then((r) => process.stdout.write(JSON.stringify(r) + "\n"))
  .catch((e) => {
    process.stderr.write(String(e?.stack ?? e) + "\n");
    process.exitCode = 1;
  })
  .finally(async () => {
    await pool.end();
    redis?.disconnect();
  });

/**
 * T6: one switch for shared state.
 *   STATE_BACKEND=memory          (default on TestNet; Phase-1 behaviour)
 *   STATE_BACKEND=postgres        everything in Postgres
 *   STATE_BACKEND=redis+postgres  nonces + limiters in Redis; queue,
 *                                 mandates, receipts, spend in Postgres
 * MainNet requires postgres or redis+postgres.
 *
 * Env (per service, normally from /etc/mandaterail/state-<service>.env with
 * service = bridge | console | demo-api; override with STATE_ENV_FILE):
 *   STATE_BACKEND, DATABASE_URL, REDIS_URL, PG_POOL_MAX
 *   (or DATABASE_URL_FILE / REDIS_URL_FILE pointing at a file with the URL).
 * Apps NEVER migrate: service roles can't create tables. They only check the
 * schema version and refuse if it's behind. Migrations run separately:
 *   pnpm --filter @mandaterail/storage migrate
 * with MIGRATE_DATABASE_URL (or DATABASE_URL) from STATE_ENV_FILE, default
 * /etc/mandaterail/state-migrate.env. MIGRATE_DATABASE_URL is never read by
 * the apps. Non-loopback Postgres/Redis require TLS with verification
 * (rediss://; PG_SSL_CA_FILE / REDIS_TLS_CA_FILE for private CAs).
 * Redis: enableReadyCheck=false (service users can't run INFO); PING only.
 * URLs and credentials are redacted from every error and log line.
 */
import { existsSync, readFileSync } from "node:fs";
import pg from "pg";
import { Redis } from "ioredis";
import {
  isMainnetProfile,
  isTokenLikePathSegment,
  type ChallengeStore,
  type MandateStore,
  type QueueLimits,
  type QueueStore,
  type RateLimitStore,
  type ReceiptLike,
  type ReceiptStore,
  type SpendStore,
} from "@mandaterail/core";
import {
  PG_SCHEMA_VERSION,
  PgChallengeStore,
  PgMandateStore,
  PgQueueStore,
  PgRateLimitStore,
  PgReceiptStore,
  PgSpendStore,
} from "./pg.js";
import { RedisChallengeStore, RedisRateLimitStore } from "./redis.js";

export type StateBackendKind = "memory" | "postgres" | "redis+postgres";
export const STATE_BACKEND_KINDS: readonly StateBackendKind[] = ["memory", "postgres", "redis+postgres"];

export class StateBackendError extends Error {}

type Env = Record<string, string | undefined>;

export function resolveStateBackendKind(env: Env = process.env, mainnet = isMainnetProfile(env.NETWORK)): StateBackendKind {
  const raw = (env.STATE_BACKEND ?? "").trim().toLowerCase();
  const kind = (raw || "memory") as StateBackendKind;
  if (!STATE_BACKEND_KINDS.includes(kind)) {
    throw new StateBackendError(`STATE_BACKEND must be one of ${STATE_BACKEND_KINDS.join(" | ")}`);
  }
  if (mainnet && kind === "memory") {
    throw new StateBackendError("MainNet requires STATE_BACKEND=postgres or redis+postgres (memory is single-process only)");
  }
  return kind;
}

/** Hide connection strings, credentials and the given secrets in a message. */
export function redactSecrets(msg: string, secrets: Array<string | undefined> = []): string {
  let out = String(msg);
  for (const s of secrets) {
    if (!s) continue;
    out = out.split(s).join("[redacted-url]");
    try {
      const u = new URL(s);
      if (u.password) out = out.split(decodeURIComponent(u.password)).join("***").split(u.password).join("***");
      if (u.username) out = out.split(`${u.username}:`).join("***:");
      // R54-P3-1: a credential in the URL path (GetBlock's /<token>/) is redacted too
      for (const seg of u.pathname.split("/").filter(Boolean)) {
        let d = seg;
        try { d = decodeURIComponent(seg); } catch { /* keep raw */ }
        if (isTokenLikePathSegment(d)) out = out.split(seg).join("***").split(d).join("***");
      }
      if (u.hostname) out = out.split(u.hostname).join("[host]");
    } catch {
      /* not a URL */
    }
  }
  // any remaining scheme://user:pass@ or scheme://user@
  out = out.replace(/([a-z][a-z0-9+.-]*:\/\/)[^\s/@]+@/gi, "$1***@");
  out = out.replace(/(password|passwd|pwd)=([^\s&]+)/gi, "$1=***");
  // R54-P3-1: token-like path segments in ANY URL left in the message (not only the listed secrets)
  out = out.replace(/(https?:\/\/[^\s/?#]+)(\/[^\s?#]*)/gi, (_m, origin: string, path: string) =>
    origin + path.split("/").map((x) => (isTokenLikePathSegment(x) ? "***" : x)).join("/"));
  out = out.replace(/([?&](?:apikey|api_key|api-key|token|key|auth)=)[^\s&#]+/gi, "$1***");
  return out;
}

function readUrl(env: Env, name: "DATABASE_URL" | "REDIS_URL"): string | undefined {
  const direct = env[name]?.trim();
  if (direct) return direct;
  const file = env[`${name}_FILE`]?.trim();
  if (!file) return undefined;
  try {
    return readFileSync(file, "utf8").trim() || undefined;
  } catch {
    throw new StateBackendError(`${name}_FILE is not readable`);
  }
}

/** Keys the apps take from their state env file (R18-P3-3: no MIGRATE_DATABASE_URL). */
export const STATE_ENV_KEYS = [
  "STATE_BACKEND", "DATABASE_URL", "DATABASE_URL_FILE", "REDIS_URL", "REDIS_URL_FILE",
  "PG_POOL_MAX", "PG_SSL_CA_FILE", "REDIS_TLS_CA_FILE", "REDIS_KEY_PREFIX",
] as const;

/**
 * Redis key prefix (default "mr"). A second stack on the same Redis (e.g. the MainNet
 * dry run next to TestNet) sets its own prefix, and its ACL users only get ~<prefix>:*.
 * Lowercase letters/digits only, starting with "mr", max 16 chars.
 */
export function redisKeyPrefix(env: Env): string {
  const v = (env.REDIS_KEY_PREFIX ?? "").trim();
  if (!v) return "mr";
  if (!/^mr[a-z0-9]{0,14}$/.test(v)) throw new StateBackendError("REDIS_KEY_PREFIX must match ^mr[a-z0-9]{0,14}$");
  return v;
}

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);
function isLoopbackOrSocket(host: string | undefined): boolean {
  if (!host) return true; // pg: no host -> local unix socket
  const h = decodeURIComponent(host).toLowerCase();
  return h.startsWith("/") || LOOPBACK_HOSTS.has(h) || /^127\./.test(h);
}

function readCa(env: Env, name: "PG_SSL_CA_FILE" | "REDIS_TLS_CA_FILE"): string | undefined {
  const f = env[name]?.trim();
  if (!f) return undefined;
  try {
    return readFileSync(f, "utf8");
  } catch {
    throw new StateBackendError(`${name} is not readable`);
  }
}

/**
 * R18-P3-3: pg config. Non-loopback hosts always use TLS with certificate
 * verification (rejectUnauthorized); sslmode=disable/allow/prefer/no-verify
 * is refused. CA bundle (e.g. RDS) via PG_SSL_CA_FILE. ssl* query params are
 * stripped so they can't override the ssl object.
 */
export function pgPoolConfig(url: string, env: Env = process.env): pg.PoolConfig {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    throw new StateBackendError("DATABASE_URL is not a valid URL");
  }
  const mode = (u.searchParams.get("sslmode") ?? "").toLowerCase();
  for (const k of ["sslmode", "ssl", "sslcert", "sslkey", "sslrootcert", "uselibpqcompat"]) u.searchParams.delete(k);
  // R19-P3-2: pg lets ?host= override the URL host, so the loopback decision
  // uses every host the driver could connect to (URL host and all ?host=).
  if (isLoopbackOrSocket(u.hostname || undefined) && u.searchParams.getAll("host").every((h) => isLoopbackOrSocket(h || undefined))) {
    return { connectionString: u.toString() };
  }
  if (["disable", "allow", "prefer", "no-verify"].includes(mode)) {
    throw new StateBackendError(`DATABASE_URL sslmode=${mode} refused for a non-loopback host (TLS with verification required)`);
  }
  return { connectionString: u.toString(), ssl: { rejectUnauthorized: true, ca: readCa(env, "PG_SSL_CA_FILE") } };
}

/** R18-P3-3: non-loopback Redis must be rediss:// with certificate verification. */
export function redisTlsOptions(url: string, env: Env = process.env): { tls?: { rejectUnauthorized: true; ca?: string } } {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    throw new StateBackendError("REDIS_URL is not a valid URL");
  }
  // R19-P3-2: ioredis applies URL query params as options, so ?host= could
  // redirect the connection; count it (and refuse tls overrides).
  if (u.searchParams.has("tls")) throw new StateBackendError("REDIS_URL must not set tls in the query string");
  const hosts = [u.hostname, ...u.searchParams.getAll("host")];
  if (hosts.every((h) => isLoopbackOrSocket(h || "localhost"))) return {};
  if (u.protocol !== "rediss:") throw new StateBackendError("REDIS_URL must use rediss:// (TLS) for a non-loopback host");
  return { tls: { rejectUnauthorized: true, ca: readCa(env, "REDIS_TLS_CA_FILE") } };
}

/**
 * Load /etc/mandaterail/state-<service>.env (or STATE_ENV_FILE) into `env`.
 * Only STATE_ENV_KEYS are taken; already-set variables win. Missing default
 * file is fine (memory backend); a missing explicit STATE_ENV_FILE throws.
 */
export function loadStateEnvFile(service: string, env: Env = process.env, extraKeys: readonly string[] = []): string | null {
  const allowed = new Set<string>([...STATE_ENV_KEYS, ...extraKeys]);
  const explicit = env.STATE_ENV_FILE?.trim();
  const file = explicit || `/etc/mandaterail/state-${service}.env`;
  if (!existsSync(file)) {
    if (explicit) throw new StateBackendError("STATE_ENV_FILE is not readable");
    return null;
  }
  let text: string;
  try {
    text = readFileSync(file, "utf8");
  } catch {
    throw new StateBackendError("state env file is not readable");
  }
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const i = t.indexOf("=");
    if (i <= 0) continue;
    const key = t.slice(0, i).replace(/^export\s+/, "").trim();
    let val = t.slice(i + 1).trim();
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) val = val.slice(1, -1);
    if (allowed.has(key) && env[key] === undefined) env[key] = val;
  }
  return file;
}

export class SchemaNotReadyError extends StateBackendError {}

/** Refuse unless the DB was migrated to exactly this build's version. */
export async function assertSchemaCurrent(pool: pg.Pool): Promise<number> {
  let v: number;
  try {
    const { rows } = await pool.query<{ v: number | null }>("SELECT max(version) AS v FROM mr_schema");
    v = rows[0]?.v ?? 0;
  } catch {
    v = 0;
  }
  if (v < PG_SCHEMA_VERSION) {
    throw new SchemaNotReadyError(`database schema v${v} is behind this build (v${PG_SCHEMA_VERSION}); run the migrate command first`);
  }
  if (v > PG_SCHEMA_VERSION) {
    throw new SchemaNotReadyError(`database schema v${v} is newer than this build (v${PG_SCHEMA_VERSION})`);
  }
  return v;
}

export interface StateBackend {
  kind: Exclude<StateBackendKind, "memory">;
  pool: pg.Pool;
  redis?: Redis;
  challengeStore(o: { audience: string; ttlMs?: number; maxEntries?: number; now?: () => number }): ChallengeStore;
  rateLimiter(o: { name: string; windowMs: number; perKey: number; global: number; now?: () => number }): RateLimitStore;
  queue<R>(name: string, limits: QueueLimits): QueueStore<R>;
  mandates(store?: string): MandateStore;
  receipts<T extends ReceiptLike>(store?: string): ReceiptStore<T>;
  spend(store?: string): SpendStore;
  close(): Promise<void>;
}

/**
 * Open the configured backend (null for memory). Connects, checks the
 * schema version (never migrates), and fails with a redacted
 * StateBackendError on any problem.
 */
export async function openStateBackend(
  env: Env = process.env,
  opts: { mainnet?: boolean; log?: (line: string) => void } = {},
): Promise<StateBackend | null> {
  const kind = resolveStateBackendKind(env, opts.mainnet ?? isMainnetProfile(env.NETWORK));
  if (kind === "memory") return null;
  const log = opts.log ?? ((l: string) => console.error(l));
  const dbUrl = readUrl(env, "DATABASE_URL");
  const redisUrl = kind === "redis+postgres" ? readUrl(env, "REDIS_URL") : undefined;
  if (!dbUrl) throw new StateBackendError(`STATE_BACKEND=${kind} requires DATABASE_URL (or DATABASE_URL_FILE)`);
  if (kind === "redis+postgres" && !redisUrl) throw new StateBackendError("STATE_BACKEND=redis+postgres requires REDIS_URL (or REDIS_URL_FILE)");
  const red = (m: unknown) => redactSecrets(m instanceof Error ? m.message : String(m), [dbUrl, redisUrl]);
  const prefix = redisKeyPrefix(env);

  let pgCfg: pg.PoolConfig;
  let redisTls: ReturnType<typeof redisTlsOptions> = {};
  try {
    pgCfg = pgPoolConfig(dbUrl, env);
    if (redisUrl) redisTls = redisTlsOptions(redisUrl, env);
  } catch (e) {
    throw new StateBackendError(red(e));
  }
  const pool = new pg.Pool({ ...pgCfg, max: Number(env.PG_POOL_MAX ?? 10) || 10 });
  pool.on("error", (e) => log(`[state] postgres idle client error: ${red(e)}`));
  let redis: Redis | undefined;
  try {
    await pool.query("SELECT 1");
    await assertSchemaCurrent(pool);
    if (redisUrl) {
      redis = new Redis(redisUrl, { lazyConnect: true, maxRetriesPerRequest: 2, enableReadyCheck: false, ...redisTls });
      redis.on("error", (e) => log(`[state] redis error: ${red(e)}`));
      await redis.connect();
      await redis.ping();
    }
  } catch (e) {
    await pool.end().catch(() => undefined);
    redis?.disconnect();
    if (e instanceof SchemaNotReadyError) throw e;
    throw new StateBackendError(`state backend ${kind} unavailable: ${red(e)}`);
  }

  return {
    kind,
    pool,
    redis,
    challengeStore: (o) => (redis ? new RedisChallengeStore(redis, { ...o, prefix }) : new PgChallengeStore(pool, o)),
    rateLimiter: (o) => (redis ? new RedisRateLimitStore(redis, { ...o, prefix }) : new PgRateLimitStore(pool, o)),
    queue: <R>(name: string, limits: QueueLimits) => new PgQueueStore<R>(pool, { queue: name, limits }),
    mandates: (store = "console") => new PgMandateStore(pool, { store }),
    receipts: <T extends ReceiptLike>(store = "demo-api") => new PgReceiptStore<T>(pool, { store }),
    spend: (store = "demo-api") => new PgSpendStore(pool, { store }),
    close: async () => {
      redis?.disconnect();
      await pool.end();
    },
  };
}

/** Startup helper for the apps: log redacted reason and exit(1) on failure. */
export async function openStateBackendOrExit(service: string, env: Env = process.env): Promise<StateBackend | null> {
  try {
    loadStateEnvFile(service, env);
    const b = await openStateBackend(env);
    console.log(`[${service}] STATE_BACKEND=${b ? b.kind : "memory"}`);
    return b;
  } catch (e) {
    const msg = e instanceof StateBackendError ? e.message : redactSecrets(String((e as Error)?.message ?? e), [env.DATABASE_URL, env.REDIS_URL]);
    console.error(`[${service}] REFUSING TO START: ${msg}`);
    process.exit(1);
  }
}

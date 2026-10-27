/**
 * Redis shared-state backends (Phase 2 T3): single-use nonces and
 * sliding-window rate limits. Every check-and-set is one Lua script, so it is
 * atomic across all processes sharing the Redis. Keys use hash tags so each
 * script touches one slot. Time comes from the caller (`now` ms); Redis key
 * TTLs are only a garbage-collection backstop.
 * Internal AI review (eng hygiene).
 */
import { randomBytes } from "node:crypto";
import type { Redis } from "ioredis";
import {
  CHALLENGE_SWEEP_GRACE_MS,
  DEFAULT_CHALLENGE_TTL_MS,
  newOperatorChallenge,
  type ChallengeConsumeResult,
  type ChallengeStore,
  type OperatorAction,
  type OperatorChallenge,
  type RateLimitStore,
} from "@mandaterail/core";

// KEYS[1] index zset (score = expiresMs), KEYS[2] entry hash
// ARGV: sweepCutoff, max, nonce, challengeJson, expiresMs, pxTtl
const ISSUE_LUA = `
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', '(' .. ARGV[1])
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[2]) then return 0 end
redis.call('HSET', KEYS[2], 'c', ARGV[4], 'e', ARGV[5], 'u', '0')
redis.call('PEXPIRE', KEYS[2], ARGV[6])
redis.call('ZADD', KEYS[1], ARGV[5], ARGV[3])
redis.call('PEXPIRE', KEYS[1], ARGV[6])
return 1
`;

// KEYS[1] entry hash. Returns {0} unknown, {1} replayed, {2, json, expiresMs} won.
const CONSUME_LUA = `
local u = redis.call('HGET', KEYS[1], 'u')
if not u then return {0} end
if u == '1' then return {1} end
redis.call('HSET', KEYS[1], 'u', '1')
return {2, redis.call('HGET', KEYS[1], 'c'), redis.call('HGET', KEYS[1], 'e')}
`;

export class RedisChallengeStore implements ChallengeStore {
  constructor(
    private readonly redis: Redis,
    private readonly opts: {
      audience: string;
      ttlMs?: number;
      maxEntries?: number;
      now?: () => number;
      prefix?: string;
    },
  ) {}
  private now(): number {
    return this.opts.now ? this.opts.now() : Date.now();
  }
  private get base(): string {
    return `${this.opts.prefix ?? "mr"}:ch:{${this.opts.audience}}`;
  }

  async issue(action: OperatorAction, subjectId: string): Promise<OperatorChallenge> {
    const now = this.now();
    const ttl = this.opts.ttlMs ?? DEFAULT_CHALLENGE_TTL_MS;
    const ch = newOperatorChallenge(action, subjectId, this.opts.audience, now, ttl);
    const ok = await this.redis.eval(
      ISSUE_LUA,
      2,
      `${this.base}:idx`,
      `${this.base}:n:${ch.nonce}`,
      // in-memory sweep deletes when now > expires + grace, i.e. expires < now - grace
      String(now - CHALLENGE_SWEEP_GRACE_MS),
      String(this.opts.maxEntries ?? 10_000),
      ch.nonce,
      JSON.stringify(ch),
      String(now + ttl),
      String(ttl + CHALLENGE_SWEEP_GRACE_MS),
    );
    if (Number(ok) !== 1) throw new Error("operator challenge store full");
    return ch;
  }

  async consume(nonce: string): Promise<ChallengeConsumeResult> {
    const r = (await this.redis.eval(CONSUME_LUA, 1, `${this.base}:n:${nonce}`)) as [number, string?, string?];
    if (Number(r[0]) === 0) return { ok: false, error: "unknown_nonce" };
    if (Number(r[0]) === 1) return { ok: false, error: "replayed_nonce" };
    if (this.now() > Number(r[2])) return { ok: false, error: "expired_nonce" };
    return { ok: true, challenge: JSON.parse(r[1] as string) as OperatorChallenge };
  }
}

// KEYS[1] global zset, KEYS[2] per-key zset; ARGV: now, cutoff, perKey, global, member, pxTtl
const TAKE_LUA = `
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[2])
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', ARGV[2])
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[4]) then return 0 end
if redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[3]) then return 0 end
redis.call('ZADD', KEYS[1], ARGV[1], ARGV[5])
redis.call('ZADD', KEYS[2], ARGV[1], ARGV[5])
redis.call('PEXPIRE', KEYS[1], ARGV[6])
redis.call('PEXPIRE', KEYS[2], ARGV[6])
return 1
`;

export class RedisRateLimitStore implements RateLimitStore {
  constructor(
    private readonly redis: Redis,
    private readonly opts: {
      name: string;
      windowMs: number;
      perKey: number;
      global: number;
      now?: () => number;
      prefix?: string;
    },
  ) {}

  async take(key: string): Promise<boolean> {
    const now = this.opts.now ? this.opts.now() : Date.now();
    const base = `${this.opts.prefix ?? "mr"}:rl:{${this.opts.name}}`;
    const ok = await this.redis.eval(
      TAKE_LUA,
      2,
      `${base}:g`,
      `${base}:k:${key}`,
      String(now),
      String(now - this.opts.windowMs),
      String(this.opts.perKey),
      String(this.opts.global),
      `${now}:${randomBytes(6).toString("hex")}`,
      String(this.opts.windowMs * 2 + 60_000),
    );
    return Number(ok) === 1;
  }
}

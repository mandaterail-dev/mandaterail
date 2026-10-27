/**
 * One behaviour suite for every backend: the in-memory implementations
 * (Phase 1 behaviour) define the contract; Postgres / Redis must match it and
 * stay atomic under concurrency.
 */
import { afterAll, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import type { IntentMandate } from "@mandaterail/schema";
import { MandateExistsError, StoreFullError, type QueueItem } from "@mandaterail/core";
import { PgMandateStore, PgReceiptStore } from "./pg.js";
import {
  backends,
  challengeStore,
  clock,
  closeShared,
  getPool,
  PG_URL,
  queueStore,
  rateLimiter,
  uid,
} from "./test-helpers.js";

afterAll(closeShared);

for (const b of backends()) {
  describe(`ChallengeStore [${b}]`, () => {
    it("issue + single-use consume; replay, unknown, expiry", async () => {
      const c = clock();
      const s = await challengeStore(b, { audience: uid("aud"), ttlMs: 1000, now: c.now });
      const ch = await s.issue("approve", "req-1");
      expect(ch.message).toContain(`nonce:${ch.nonce}`);
      expect(await s.consume(ch.nonce)).toEqual({ ok: true, challenge: ch });
      expect(await s.consume(ch.nonce)).toEqual({ ok: false, error: "replayed_nonce" });
      expect(await s.consume("nope")).toEqual({ ok: false, error: "unknown_nonce" });
      const late = await s.issue("list", "pending");
      c.t += 1001;
      expect(await s.consume(late.nonce)).toEqual({ ok: false, error: "expired_nonce" });
      expect(await s.consume(late.nonce)).toEqual({ ok: false, error: "replayed_nonce" });
    });

    it("audiences are isolated (bridge nonce is unknown at the console)", async () => {
      const a = await challengeStore(b, { audience: uid("bridge") });
      const other = await challengeStore(b, { audience: uid("console") });
      const ch = await a.issue("list", "pending");
      expect(await other.consume(ch.nonce)).toEqual({ ok: false, error: "unknown_nonce" });
      expect((await a.consume(ch.nonce)).ok).toBe(true);
    });

    it("live-entry cap throws; swept after expiry + grace", async () => {
      const c = clock();
      const s = await challengeStore(b, { audience: uid("cap"), ttlMs: 1000, maxEntries: 3, now: c.now });
      for (let i = 0; i < 3; i++) await s.issue("approve", `r${i}`);
      await expect(Promise.resolve().then(() => s.issue("approve", "r3"))).rejects.toThrow(/full/);
      c.t += 1000 + 60_001;
      await expect(Promise.resolve(s.issue("approve", "r4"))).resolves.toHaveProperty("nonce");
    });

    it("50 concurrent consumes of one nonce: exactly one wins", async () => {
      const s = await challengeStore(b, { audience: uid("race") });
      const ch = await s.issue("approve", "x");
      const rs = await Promise.all(Array.from({ length: 50 }, () => Promise.resolve(s.consume(ch.nonce))));
      expect(rs.filter((r) => r.ok)).toHaveLength(1);
      expect(rs.filter((r) => !r.ok && r.error === "replayed_nonce")).toHaveLength(49);
    });
  });

  describe(`RateLimitStore [${b}]`, () => {
    it("per-key and global sliding window", async () => {
      const c = clock();
      const l = await rateLimiter(b, { name: uid("rl"), windowMs: 60_000, perKey: 2, global: 3, now: c.now });
      expect(await l.take("a")).toBe(true);
      expect(await l.take("a")).toBe(true);
      expect(await l.take("a")).toBe(false); // per-key
      expect(await l.take("b")).toBe(true);
      expect(await l.take("c")).toBe(false); // global
      c.t += 30_000;
      expect(await l.take("c")).toBe(false); // still inside the window
      c.t += 30_000; // first two (t0) now exactly at the cutoff -> pruned
      expect(await l.take("a")).toBe(true);
      expect(await l.take("c")).toBe(true);
    });

    it("100 concurrent takes, global 10: exactly 10 admitted", async () => {
      const l = await rateLimiter(b, { name: uid("rlc"), windowMs: 60_000, perKey: 100, global: 10 });
      const rs = await Promise.all(Array.from({ length: 100 }, (_, i) => Promise.resolve(l.take(`k${i % 7}`))));
      expect(rs.filter(Boolean)).toHaveLength(10);
    });
  });
}

const limits = { maxPending: 3, pendingTtlMs: 10_000, retentionMs: 20_000, maxPendingPerClient: 2 };
const item = (id: string, clientKey: string, now: number): QueueItem<{ message: string }> => ({
  id,
  status: "pending",
  createdAt: new Date(now).toISOString(),
  createdMs: now,
  clientKey,
  request: { message: `m-${id}` },
  requesterTokenHash: createHash("sha256").update(id).digest(),
});

for (const b of backends().filter((x) => x !== "redis") as ("memory" | "postgres")[]) {
  describe(`QueueStore [${b}]`, () => {
    it("caps, CAS finalize, collected-only eviction, TTL and retention", async () => {
      const c = clock();
      const q = await queueStore<{ message: string }>(b, limits);
      expect(await q.insert(item("a", "k1", c.t), c.t)).toBe("ok");
      expect(await q.insert(item("b", "k1", c.t), c.t)).toBe("ok");
      expect(await q.insert(item("c", "k1", c.t), c.t)).toBe("client_pending_cap");
      expect(await q.insert(item("c", "k2", c.t), c.t)).toBe("ok");
      expect(await q.insert(item("d", "k3", c.t), c.t)).toBe("queue_full");
      expect(await q.countPending(c.t)).toBe(3);

      const got = await q.get("a", c.t);
      expect(got?.request).toEqual({ message: "m-a" });
      expect(Buffer.from(got!.requesterTokenHash).equals(createHash("sha256").update("a").digest())).toBe(true);

      c.t += 1;
      const fin = await q.finalize("a", "approved", { signature: "sig", publicKey: "pk", address: "addr" }, c.t);
      expect(fin.ok && fin.item.signature).toBe("sig");
      expect(await q.finalize("a", "rejected", {}, c.t)).toEqual({ ok: false, error: "not_pending", status: "approved" });
      expect(await q.finalize("zz", "rejected", {}, c.t)).toEqual({ ok: false, error: "not_found" });
      // uncollected result is never evicted early
      expect(await q.insert(item("d", "k3", c.t), c.t)).toBe("queue_full");
      await q.markCollected("a");
      expect(await q.insert(item("d", "k3", c.t), c.t)).toBe("ok");
      expect(await q.get("a", c.t)).toBeNull();
      expect((await q.list(c.t)).map((i) => i.id)).toEqual(["b", "c", "d"]);

      c.t += 9_999; // b, c (created t0) reach the pending TTL; d (t0+1) not yet
      expect((await q.get("b", c.t))?.status).toBe("expired");
      expect(await q.countPending(c.t)).toBe(1); // d
      c.t += 20_000; // expired b, c past retention; d expired at t0+10001, still retained
      expect(await q.get("b", c.t)).toBeNull();
      expect((await q.list(c.t)).map((i) => [i.id, i.status])).toEqual([["d", "expired"]]);
    });

    it("concurrent approve/reject of one item: exactly one wins", async () => {
      const c = clock();
      const q = await queueStore<{ message: string }>(b, { ...limits, maxPending: 100 });
      await q.insert(item("x", "k", c.t), c.t);
      const rs = await Promise.all(
        Array.from({ length: 20 }, (_, i) =>
          Promise.resolve(q.finalize("x", i % 2 ? "approved" : "rejected", { signature: `s${i}` }, c.t)),
        ),
      );
      expect(rs.filter((r) => r.ok)).toHaveLength(1);
    });

    it("concurrent inserts never exceed the caps", async () => {
      const c = clock();
      const q = await queueStore<{ message: string }>(b, { ...limits, maxPending: 10, maxPendingPerClient: 4 });
      const rs = await Promise.all(
        Array.from({ length: 40 }, (_, i) => Promise.resolve(q.insert(item(`i${i}`, `k${i % 5}`, c.t), c.t))),
      );
      expect(rs.filter((r) => r === "ok")).toHaveLength(10);
      const list = await q.list(c.t);
      expect(list).toHaveLength(10);
      for (let k = 0; k < 5; k++) expect(list.filter((i) => i.clientKey === `k${k}`).length).toBeLessThanOrEqual(4);
    });
  });
}

const mk = (id: string): IntentMandate =>
  ({
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
  }) as IntentMandate;

describe.skipIf(!PG_URL)("PgMandateStore / PgReceiptStore [postgres]", () => {
  it("create, verified flag, order, duplicate, revoke", async () => {
    const s = new PgMandateStore(await getPool(), { store: uid("m") });
    const a = await s.create(mk("a"), { signatureVerified: true });
    expect(a.server.signatureVerified).toBe(true);
    await s.create(mk("b"));
    await expect(s.create(mk("a"))).rejects.toBeInstanceOf(MandateExistsError);
    expect((await s.list()).map((r) => [r.mandate.id, r.server.signatureVerified])).toEqual([
      ["a", true],
      ["b", false],
    ]);
    const r = await s.revoke("a");
    expect(r?.mandate.revoked).toBe(true);
    expect(r?.server.signatureVerified).toBe(true);
    expect(await s.revoke("zz")).toBeNull();
    expect((await s.get("a"))?.mandate).toEqual({ ...mk("a"), revoked: true, createdAt: a.mandate.createdAt, expiresAt: a.mandate.expiresAt });
  });

  it("concurrent creates never exceed the cap; create + revoke never resurrects", async () => {
    const s = new PgMandateStore(await getPool(), { store: uid("mc") });
    const rs = await Promise.allSettled(Array.from({ length: 25 }, (_, i) => s.create(mk(`k${i}`), { maxMandates: 10 })));
    expect(rs.filter((r) => r.status === "fulfilled")).toHaveLength(10);
    expect(rs.filter((r) => r.status === "rejected").every((r) => (r as PromiseRejectedResult).reason instanceof StoreFullError)).toBe(true);

    const s2 = new PgMandateStore(await getPool(), { store: uid("mr") });
    await s2.create(mk("victim"));
    await Promise.all([s2.revoke("victim"), ...Array.from({ length: 20 }, (_, i) => s2.create(mk(`c${i}`)))]);
    expect((await s2.get("victim"))?.mandate.revoked).toBe(true);
    expect(await s2.list()).toHaveLength(21);
  });

  it("receipts sumSpentMicro per payer since a time, exact", async () => {
    const { toMicro } = await import("@mandaterail/core");
    type R = { receiptId: string; payer: string; amount: string; createdAt: string };
    const r = new PgReceiptStore<R>(await getPool(), { store: uid("spend") });
    const day = Date.parse("2026-10-15T00:00:00Z");
    const at = (ms: number) => new Date(ms).toISOString();
    await r.add({ receiptId: "a", payer: "P", amount: "0.1", createdAt: at(day + 1000) });
    await r.add({ receiptId: "b", payer: "P", amount: "0.2", createdAt: at(day + 2000) });
    await r.add({ receiptId: "c", payer: "P", amount: "4.70", createdAt: at(day + 3000) });
    await r.add({ receiptId: "d", payer: "P", amount: "9", createdAt: at(day - 1) });
    await r.add({ receiptId: "e", payer: "Q", amount: "1", createdAt: at(day + 1) });
    expect(await r.sumSpentMicro("P", day)).toBe(toMicro("5"));
    expect(await r.sumSpentMicro("Z", day)).toBe(0n);
  });

  it("receipts: add, get, latest first", async () => {
    const r = new PgReceiptStore<{ receiptId: string; n: number }>(await getPool(), { store: uid("r") });
    for (let i = 0; i < 3; i++) await r.add({ receiptId: `r${i}`, n: i });
    expect(await r.get("r1")).toEqual({ receiptId: "r1", n: 1 });
    expect((await r.list(2)).map((x) => x.receiptId)).toEqual(["r2", "r1"]);
  });
});

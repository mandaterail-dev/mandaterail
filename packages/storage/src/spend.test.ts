/**
 * T7-P2-1/2 spend store conformance (memory + Postgres) and the N-process
 * daily-cap race against Postgres. Postgres parts skip without MR_TEST_PG_URL.
 */
import { afterAll, describe, expect, it } from "vitest";
import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { promisify } from "node:util";
import { checkSpendCaps, InMemorySpendStore, reconcileSpend, toMicro, utcDayStartMs, type SpendStore } from "@mandaterail/core";
import { PgSpendStore } from "./pg.js";
import { closeShared, getPool, PG_URL, uid } from "./test-helpers.js";

afterAll(closeShared);
const NOW = Date.parse("2026-10-15T15:00:00Z");
const caps = { perPaymentMicro: toMicro("1"), perDayMicro: toMicro("5") };
const kinds = ["memory", ...(PG_URL ? ["postgres"] : [])] as const;
const make = async (k: string): Promise<SpendStore> => (k === "postgres" ? new PgSpendStore(await getPool(), { store: uid("sp") }) : new InMemorySpendStore());

describe("SpendStore conformance", () => {
  for (const k of kinds) {
    it(`[${k}] reserve / caps / finalize CAS / reconcile / recordSettled / day window`, async () => {
      const s = await make(k);
      const ids: string[] = [];
      for (let i = 0; i < 5; i++) {
        const r = await checkSpendCaps({ payer: "P", amountMicro: toMicro("1"), caps, store: s, nowMs: NOW });
        expect(r.ok).toBe(true);
        if (r.ok) ids.push(r.reservationId!);
      }
      expect(await checkSpendCaps({ payer: "P", amountMicro: 1n, caps, store: s, nowMs: NOW })).toMatchObject({ ok: false, reason: "daily_cap_exceeded" });
      expect(await checkSpendCaps({ payer: "P", amountMicro: toMicro("1.01"), caps, store: s, nowMs: NOW })).toMatchObject({ ok: false, reason: "per_payment_cap_exceeded" });
      expect(await s.finalize(ids[0]!, "released", NOW)).toBe(true);
      expect(await s.finalize(ids[0]!, "settled", NOW)).toBe(false);
      expect(await s.finalize(ids[1]!, "settled", NOW, "TX1")).toBe(true);
      expect(await s.finalize(ids[2]!, "ambiguous", NOW)).toBe(true);
      expect((await s.get(ids[1]!))!).toMatchObject({ status: "settled", txId: "TX1", payer: "P", amountMicro: toMicro("1") });
      expect(await s.attachTxId(ids[3]!, "TX3", NOW, 777)).toBe(true);
      expect(await s.get(ids[3]!)).toMatchObject({ status: "pending", txId: "TX3", lastValid: 777 });
      expect(await s.attachTxId(ids[1]!, "TXX", NOW)).toBe(false);
      expect(await s.spentSinceMicro("P", utcDayStartMs(NOW))).toBe(toMicro("4"));
      if (k === "postgres") {
        // R23-P3-1: on Postgres the generic store path cannot release; only mr_spend_release (with proof) can.
        await expect(reconcileSpend(s, async () => "released", { nowMs: NOW + 3600_000, pendingOlderThanMs: 900_000 })).rejects.toThrow(/disabled/);
        expect(await s.finalize(ids[3]!, "released", NOW)).toBe(false); // txId pinned: the app can no longer release it
        expect(await s.spentSinceMicro("P", utcDayStartMs(NOW))).toBe(toMicro("4"));
      } else {
        const out = await reconcileSpend(s, async (r) => (r.id === ids[2] ? "released" : "unknown"), { nowMs: NOW + 3600_000, pendingOlderThanMs: 900_000 });
        expect(out).toEqual({ settled: 0, released: 1, unknown: 2 }); // ids[3], ids[4] stale pending stay counted
        expect(await s.spentSinceMicro("P", utcDayStartMs(NOW))).toBe(toMicro("3"));
      }
      expect(await s.recordSettled({ id: "imp-1", payer: "Q", amountMicro: toMicro("2"), createdMs: NOW })).toBe(true);
      expect(await s.recordSettled({ id: "imp-1", payer: "Q", amountMicro: toMicro("2"), createdMs: NOW })).toBe(false);
      expect(await s.spentSinceMicro("Q", utcDayStartMs(NOW))).toBe(toMicro("2"));
      expect(await s.spentSinceMicro("Q", utcDayStartMs(NOW) + 86_400_000)).toBe(0n);
    });

    it(`[${k}] in-process concurrency: 40 parallel 0.25 reserves on a 5.00 cap -> exactly 20`, async () => {
      const s = await make(k);
      const rs = await Promise.all(
        Array.from({ length: 40 }, () => checkSpendCaps({ payer: "R", amountMicro: toMicro("0.25"), caps, store: s, nowMs: NOW })),
      );
      expect(rs.filter((r) => r.ok)).toHaveLength(20);
      expect(await s.spentSinceMicro("R", utcDayStartMs(NOW))).toBe(toMicro("5"));
    });
  }
});

const run = promisify(execFile);
const here = path.dirname(fileURLToPath(import.meta.url));
const TSX = path.resolve(here, "../node_modules/.bin/tsx");
const WORKER = path.resolve(here, "mp-worker.ts");

describe.skipIf(!PG_URL)("T7-P2-1: N processes cannot spend more than the cap [postgres]", () => {
  it("4 processes x 10 parallel 1-USDC reserves, cap 5 -> exactly 5 reserved", async () => {
    await getPool(); // migrated
    const store = uid("mp-spend");
    const startAt = Date.now() + 2500;
    const job = { op: "reserve", store, payer: "PAYER", n: 10, amountMicro: "1000000", perDayMicro: "5000000", startAt };
    const outs = await Promise.all(
      Array.from({ length: 4 }, () => run(TSX, [WORKER, JSON.stringify(job)], { env: process.env, timeout: 30_000 })),
    );
    const total = outs.map((o) => JSON.parse(o.stdout.trim().split("\n").pop()!).reserved as number).reduce((a, b) => a + b, 0);
    expect(total).toBe(5);
    const s = new PgSpendStore(await getPool(), { store });
    expect(await s.spentSinceMicro("PAYER", 0)).toBe(toMicro("5"));
  });
});

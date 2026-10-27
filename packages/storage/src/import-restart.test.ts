/**
 * ST-P3-5: JSON -> Postgres import, and a real restart of Postgres + Redis
 * (only the throwaway services from scripts/with-state-services.sh).
 */
import { afterAll, describe, expect, it } from "vitest";
import { execFile, execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import algosdk from "algosdk";
import { signMandate, toMicro, utcDayStartMs } from "@mandaterail/core";
import { importConsoleJson, importReceiptsJson } from "./import-json.js";
import { openStateBackend, type StateBackend } from "./backend.js";
import { PgMandateStore, PgReceiptStore, PgSpendStore } from "./pg.js";
import { closeShared, getPool, PG_URL, REDIS_URL, uid } from "./test-helpers.js";

afterAll(closeShared);
const run = promisify(execFile);

function mandate(id: string, signed: boolean) {
  const a = algosdk.generateAccount();
  const u = {
    id, principal: a.addr.toString(), agent: "did:example:a", maxAmount: "1.00", asset: "USDC", allowlist: ["m"],
    expiresAt: new Date(Date.now() + 3600_000).toISOString(), revoked: false, nonce: id, createdAt: new Date().toISOString(),
  };
  return { ...u, signature: signed ? signMandate(u as never, a.sk) : null };
}

describe.skipIf(!PG_URL)("ST-P3-5 JSON import", () => {
  it("console mandates: v2 + legacy, verified only if the signature re-verifies; idempotent", async () => {
    const pool = await getPool();
    const dir = mkdtempSync(path.join(tmpdir(), "mr-imp-"));
    const good = mandate("good", true);
    const forged = { ...mandate("forged", true), maxAmount: "999.00" }; // tampered after signing
    const file = path.join(dir, "mandates.json");
    writeFileSync(file, JSON.stringify([
      { mandate: good, server: { signatureVerified: true, verifiedAt: "2026-10-01T00:00:00.000Z" } },
      { mandate: forged, server: { signatureVerified: true } },
      mandate("legacy", true), // bare legacy record: never verified
      { mandate: { id: "broken" }, server: {} },
    ]));
    const store = uid("console");
    expect(await importConsoleJson(pool, file, { store })).toEqual({ read: 4, imported: 3, skipped: 0, invalid: 1, verified: 1 });
    expect(await importConsoleJson(pool, file, { store })).toMatchObject({ imported: 0, skipped: 3 });
    const s = new PgMandateStore(pool, { store });
    expect((await s.get("good"))!.server).toEqual({ signatureVerified: true, verifiedAt: "2026-10-01T00:00:00.000Z" });
    expect((await s.get("forged"))!.server.signatureVerified).toBe(false);
    expect((await s.get("legacy"))!.server.signatureVerified).toBe(false);
    expect((await s.list()).map((m) => m.mandate.id)).toEqual(["good", "forged", "legacy"]);
  });

  it("receipts: imported in order + settled spend rows count toward today's cap", async () => {
    const pool = await getPool();
    const dir = mkdtempSync(path.join(tmpdir(), "mr-imp-"));
    const now = Date.now();
    const rec = (id: string, payer: string, amount: string, at: number) => ({
      receiptId: id, mandateId: "m", txId: `TX-${id}`, network: "x", payer, merchant: "M", amount, asset: "10458941",
      createdAt: new Date(at).toISOString(), explorerUrl: "u",
    });
    const file = path.join(dir, "receipts.json");
    writeFileSync(file, JSON.stringify([
      rec("a", "P", "0.01", now - 1000), rec("b", "P", "2.00", now - 500), rec("old", "P", "3", utcDayStartMs(now) - 1),
      { receiptId: "bad", payer: "P", amount: "-1", createdAt: "x" },
    ]));
    const store = uid("demo");
    expect(await importReceiptsJson(pool, file, { store })).toEqual({ read: 4, imported: 3, skipped: 0, invalid: 1, spendRows: 3 });
    expect(await importReceiptsJson(pool, file, { store })).toMatchObject({ imported: 0, skipped: 3, spendRows: 0 });
    expect((await new PgReceiptStore(pool, { store }).list(10)).map((r) => r.receiptId)).toEqual(["old", "b", "a"]);
    const sp = new PgSpendStore(pool, { store });
    expect(await sp.spentSinceMicro("P", utcDayStartMs(now))).toBe(toMicro("2.01"));
    expect((await sp.get("receipt:b"))!).toMatchObject({ status: "settled", txId: "TX-b" });
  });

  it("migrate + import CLIs run end to end and never print the URL", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "mr-cli-"));
    const envFile = path.join(dir, "state-migrate.env");
    writeFileSync(envFile, `MIGRATE_DATABASE_URL=${PG_URL}\n`);
    const tsx = path.resolve(__dirname, "../node_modules/.bin/tsx");
    const env = { ...process.env, STATE_ENV_FILE: envFile, DATABASE_URL: "", MIGRATE_DATABASE_URL: undefined } as NodeJS.ProcessEnv;
    delete env.MIGRATE_DATABASE_URL;
    const m = await run(tsx, [path.resolve(__dirname, "migrate-cli.ts")], { env });
    expect(m.stdout).toMatch(/schema v\d+ -> v\d+/);
    const rf = path.join(dir, "r.json");
    writeFileSync(rf, "[]");
    const i = await run(tsx, [path.resolve(__dirname, "import-cli.ts"), "--receipts", rf, "--receipts-store", uid("cli")], { env });
    expect(i.stdout).toContain('"read":0');
    expect(m.stdout + m.stderr + i.stdout + i.stderr).not.toContain(PG_URL!);
  });
});

const PG_DATA = process.env.MR_TEST_PG_DATA;
const R_PORT = process.env.MR_TEST_REDIS_PORT;
const R_DIR = process.env.MR_TEST_REDIS_DIR;
const canRestart = Boolean(PG_URL && REDIS_URL && PG_DATA && R_PORT && R_DIR);

async function until(fn: () => Promise<unknown>, ms = 15_000) {
  const end = Date.now() + ms;
  for (;;) {
    try {
      return await fn();
    } catch (e) {
      if (Date.now() > end) throw e;
      await new Promise((r) => setTimeout(r, 200));
    }
  }
}

describe.skipIf(!canRestart)("ST-P3-5: Postgres + Redis restart (redis+postgres backend)", () => {
  let b: StateBackend | undefined;
  afterAll(async () => { await b?.close(); });

  it("state survives; the same backend clients recover; single-use and caps still hold", async () => {
    await getPool(); // migrated
    b = (await openStateBackend({ STATE_BACKEND: "redis+postgres", DATABASE_URL: PG_URL, REDIS_URL }, { mainnet: true, log: () => undefined }))!;
    const audience = uid("aud");
    const chal = b.challengeStore({ audience, ttlMs: 600_000 });
    const ch = await chal.issue("approve", "req-1");
    const used = await chal.issue("approve", "req-2");
    expect((await chal.consume(used.nonce)).ok).toBe(true);
    const lim = b.rateLimiter({ name: uid("rl"), windowMs: 600_000, perKey: 2, global: 10 });
    expect(await lim.take("ip")).toBe(true);
    expect(await lim.take("ip")).toBe(true);
    const ms = uid("m");
    await b.mandates(ms).create(mandate("m-1", false) as never);
    const spStore = uid("sp");
    const caps = { perPaymentMicro: toMicro("1"), perDayMicro: toMicro("2") };
    expect((await b.spend(spStore).reserve({ id: "r1", payer: "P", amountMicro: toMicro("1"), caps, nowMs: Date.now() })).ok).toBe(true);

    // restart both services
    execFileSync("pg_ctl", ["-D", PG_DATA!, "-m", "fast", "-w", "restart", "-l", path.join(PG_DATA!, "..", "pg-restart.log")], { stdio: "ignore" });
    execFileSync("redis-cli", ["-p", R_PORT!, "shutdown"], { stdio: "ignore" });
    execFileSync("redis-server", [
      "--port", R_PORT!, "--bind", "127.0.0.1", "--save", "", "--appendonly", "yes", "--appendfsync", "always",
      "--daemonize", "yes", "--dir", R_DIR!, "--logfile", path.join(R_DIR!, "redis.log"),
    ]);
    await until(() => b!.redis!.ping());
    await until(() => b!.pool.query("SELECT 1"));

    // Redis (AOF): nonce state survived
    expect(await chal.consume(ch.nonce)).toMatchObject({ ok: true });
    expect(await chal.consume(ch.nonce)).toMatchObject({ ok: false, error: "replayed_nonce" });
    expect(await chal.consume(used.nonce)).toMatchObject({ ok: false, error: "replayed_nonce" });
    expect(await lim.take("ip")).toBe(false); // per-key 2 already used
    // Postgres: mandates + spend survived
    expect((await b.mandates(ms).get("m-1"))!.mandate.id).toBe("m-1");
    const sp = b.spend(spStore);
    expect((await sp.reserve({ id: "r2", payer: "P", amountMicro: toMicro("1"), caps, nowMs: Date.now() })).ok).toBe(true);
    expect(await sp.reserve({ id: "r3", payer: "P", amountMicro: 1n, caps, nowMs: Date.now() })).toMatchObject({ ok: false, reason: "daily_cap_exceeded" });
  }, 60_000);
});

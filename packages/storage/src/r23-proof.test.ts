/**
 * R23 (internal reviewer run 23) on real Postgres:
 *  - R23-P2-1: mr_spend_release checks a typed proof itself (pinned tx_id +
 *    last_valid, margin >= 0, round_checked > last_valid + margin, indexer 404,
 *    genesis = the write-once mr_network marker); forced release refused when
 *    the marker is mainnet; proof stored in its own columns.
 *  - R23-P3-1: mr_spend_guard refuses status changes / re-pinning outside the
 *    SECURITY DEFINER functions (flag alone is not enough); app roles minimal.
 *  - R23-P3-3: settle needs a pinned, non-null txId.
 *  - R23-P3-4: monitor alerts on needsRelease rows older than the limit.
 */
import { afterAll, describe, expect, it } from "vitest";
import { execFile, spawn } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import pg from "pg";
import { MAINNET_PROFILE, TESTNET_PROFILE, toMicro } from "@mandaterail/core";
import { migratePostgres, PgSpendStore } from "./pg.js";
import { MonitorConfigError, runMonitor } from "./monitor.js";
import { reconcileSpendPg, spendAudit, staleSpendCounts } from "./spend-ops.js";
import { closeShared, getPool, PG_URL, uid, seedTestProviders } from "./test-helpers.js";

afterAll(closeShared);
const run = promisify(execFile);
const SQL = path.resolve(__dirname, "../../../deploy/sql/t11-mr-reconcile-role.sql");
const caps = { perPaymentMicro: toMicro("1"), perDayMicro: toMicro("5") };
const pwArgs = ["-v", "pw=t-rec-pw", "-v", "mon_pw=t-mon-pw", "-v", "rel_pw=t-rel-pw"];
const applyRoles = (url = PG_URL!) => run("psql", ["-X", "-q", "-v", "ON_ERROR_STOP=1", ...pwArgs, "-d", url, "-f", SQL]);
const TN = TESTNET_PROFILE.caip2.slice(9);
const MN = MAINNET_PROFILE.caip2.slice(9);
function poolAs(role: string, pw: string, base = PG_URL!): pg.Pool {
  const u = new URL(base);
  u.username = role;
  u.password = pw;
  const p = new pg.Pool({ connectionString: u.toString(), max: 2 });
  p.on("error", () => undefined);
  return p;
}
// R24: two observations; the v7-style (tx, genesis, round, lastValid, margin, status) maps onto both.
const REL = "SELECT * FROM mr_spend_release($1,$2,$3,'david','operator check',$4,$7,$8,'idx-a.example','indexer',$5,$6,$9,'idx-b.example','indexer',$5,$6,$9)";
async function pinnedAmbiguous(s: PgSpendStore, id: string, tx: string | null, lv: number | null) {
  await s.reserve({ id, payer: "P", amountMicro: 1n, caps, nowMs: Date.now() - 3_600_000 });
  if (tx) await s.attachTxId(id, tx, Date.now(), lv);
  await s.finalize(id, "ambiguous", Date.now());
}

describe.skipIf(!PG_URL)("R23 DB-checked proof, network marker, spend guard [postgres]", () => {
  it("R23-P2-1: network marker is set by migrate and write-once", async () => {
    const pool = await getPool();
    expect((await pool.query("SELECT network, genesis_hash FROM mr_network")).rows).toEqual([{ network: "testnet", genesis_hash: TN }]);
    await expect(pool.query("UPDATE mr_network SET network = 'testnet'")).rejects.toThrow(/write-once/);
    await expect(pool.query("DELETE FROM mr_network")).rejects.toThrow(/write-once/);
    await expect(pool.query("TRUNCATE mr_network")).rejects.toThrow(/write-once/);
    await expect(pool.query("INSERT INTO mr_network (network, genesis_hash) VALUES ('mainnet', 'x')")).rejects.toThrow(/duplicate key|unique/);
  });

  it("R23-P2-1: mr_spend_release verifies the typed proof in the DB and stores it in columns", async () => {
    await applyRoles();
    const pool = await getPool();
    const store = uid("r23");
    const s = new PgSpendStore(pool, { store });
    await pinnedAmbiguous(s, "gone", "TXGONE", 900);
    await pinnedAmbiguous(s, "notx", null, null);
    const rel = poolAs("mr_release", "t-rel-pw");
    try {
      const q = (id: string, action: string, tx: string | null, gh: string | null, round: number | null, lv: number | null, m: number | null, st: number | null) =>
        rel.query(REL, [store, id, action, tx, gh, round, lv, m, st]);
      // the run-23 forgery: free-text "proof" with nothing typed is refused
      await expect(rel.query(`SELECT * FROM mr_spend_release($1,'gone','manual-release','x','ok | proof: FORGED',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)`, [store])).rejects.toThrow(/needs txId/);
      await expect(q("gone", "manual-release", "TXGONE", TN, 1500, 900, -1, 404)).rejects.toThrow(/margin must be >= 0/);
      await expect(q("gone", "manual-release", "TXGONE", TN, 999, 1000, 0, 404)).rejects.toThrow(/not past lastValid/);
      await expect(q("gone", "manual-release", "TXGONE", TN, 910, 900, 10, 404)).rejects.toThrow(/not past lastValid/); // round == lv + margin
      await expect(q("gone", "manual-release", "TXGONE", TN, 1500, 900, 10, 200)).rejects.toThrow(/404/);
      await expect(q("gone", "manual-release", "TXGONE", MN, 1500, 900, 10, 404)).rejects.toThrow(/genesis hash does not match/);
      await expect(q("notx", "manual-release", "TXANY", TN, 1500, 900, 10, 404)).rejects.toThrow(/no pinned tx_id/);
      // the proof must be for the row's own txn and lastValid (a lower claimed lastValid is not accepted)
      expect((await q("gone", "manual-release", "TXOTHER", TN, 1500, 900, 10, 404)).rows[0]).toEqual({ ok: false, from_status: "ambiguous" });
      expect((await q("gone", "manual-release", "TXGONE", TN, 1500, 500, 10, 404)).rows[0]).toEqual({ ok: false, from_status: "ambiguous" });
      expect((await s.get("gone"))!.status).toBe("ambiguous");
      expect((await q("gone", "manual-release", "TXGONE", TN, 1500, 900, 10, 404)).rows[0]).toEqual({ ok: true, from_status: "ambiguous" });
      expect(await spendAudit(pool, store, "gone")).toMatchObject([{
        action: "manual-release", reason: "operator check", proof_tx_id: "TXGONE", proof_genesis_hash: TN,
        proof_round_checked: "1500", proof_last_valid: "900", proof_margin: 10, proof_indexer_status: 404,
      }]);
      // TestNet marker: forced release is allowed (and audited without proof columns)
      expect((await q("notx", "manual-release-forced", null, null, null, null, null, null)).rows[0]).toMatchObject({ ok: true });
      expect((await spendAudit(pool, store, "notx"))[0]).toMatchObject({ action: "manual-release-forced", proof_round_checked: null });
    } finally {
      await rel.end();
    }
  });

  it("R23-P2-1: on a database whose marker is mainnet, forced release is refused by the DB", async () => {
    const admin = await getPool();
    const db = `mr_r23_${uid("m").replace(/-/g, "_")}`;
    await admin.query(`CREATE DATABASE ${db}`);
    const url = PG_URL!.replace(/\/[^/]*$/, `/${db}`);
    const p = new pg.Pool({ connectionString: url, max: 2 });
    p.on("error", () => undefined);
    try {
      expect(await migratePostgres(p, { network: "mainnet", allowMainnet: true, verifyNetwork: async (p) => ({ genesisHash: p.caip2.slice(9) }) })).toMatchObject({ network: "mainnet" });
      await expect(migratePostgres(p, { network: "testnet", verifyNetwork: async (p) => ({ genesisHash: p.caip2.slice(9) }) })).rejects.toThrow(/marker is mainnet/);
      await seedTestProviders(p);
      await applyRoles(url);
      const s = new PgSpendStore(p, { store: "demo-api" });
      await pinnedAmbiguous(s, "a", "TXA", 900);
      const rel = poolAs("mr_release", "t-rel-pw", url);
      try {
        await expect(rel.query(REL, ["demo-api", "a", "manual-release-forced", null, null, null, null, null, null])).rejects.toThrow(/refused on mainnet/);
        // v11 (attested-release-signer): every unsigned release is refused on mainnet, whatever the proof;
        // mainnet releases go through mr_spend_release_attested (v11-attested.test.ts).
        await expect(rel.query(REL, ["demo-api", "a", "manual-release", "TXA", TN, 1500, 900, 10, 404])).rejects.toThrow(/unsigned releases are refused on mainnet/);
        await expect(rel.query(REL, ["demo-api", "a", "manual-release", "TXA", MN, 1500, 900, 10, 404])).rejects.toThrow(/unsigned releases are refused on mainnet/);
      } finally {
        await rel.end();
      }
    } finally {
      await p.end();
      await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`);
    }
  });

  it("R23-P3-1: status changes only through the definer functions; the session flag alone is not enough", async () => {
    const pool = await getPool();
    const store = uid("guard");
    const s = new PgSpendStore(pool, { store });
    await s.reserve({ id: "a", payer: "P", amountMicro: 1n, caps, nowMs: Date.now() });
    // even the owner cannot move status directly (no flag)
    await expect(pool.query("UPDATE mr_spend SET status = 'released' WHERE store = $1", [store])).rejects.toThrow(/only through the mr_spend_\* functions/);
    await expect(pool.query("UPDATE mr_spend SET amount_micro = 999 WHERE store = $1", [store])).rejects.toThrow(/immutable/);
    await expect(pool.query("DELETE FROM mr_spend WHERE store = $1", [store])).rejects.toThrow(/DELETE refused/);
    await expect(pool.query("INSERT INTO mr_spend (store, id, payer, amount_micro, status, created_ms, updated_ms) VALUES ($1,'x','P',1,'released',1,1)", [store])).rejects.toThrow(/pending or settled/);
    // a non-owner with full UPDATE and the flag set by hand is still refused
    await pool.query("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='mr_t23_upd') THEN CREATE ROLE mr_t23_upd LOGIN PASSWORD 't-upd-pw'; END IF; END $$");
    await pool.query("GRANT SELECT, UPDATE ON mr_spend TO mr_t23_upd");
    const upd = poolAs("mr_t23_upd", "t-upd-pw");
    try {
      const c = await upd.connect();
      try {
        await c.query("BEGIN");
        await c.query("SELECT set_config('mr.spend_fn', 'on', true)");
        await expect(c.query("UPDATE mr_spend SET status = 'released' WHERE store = $1", [store])).rejects.toThrow(/only through/);
        await c.query("ROLLBACK");
      } finally {
        c.release();
      }
      // pin once, then the pinned tx_id / last_valid cannot be changed directly
      expect(await s.attachTxId("a", "TXA", Date.now(), 100)).toBe(true);
      await expect(upd.query("UPDATE mr_spend SET tx_id = 'TXEVIL' WHERE store = $1", [store])).rejects.toThrow(/pinned once/);
      expect(await s.attachTxId("a", "TXB", Date.now(), 1)).toBe(false);
    } finally {
      await upd.end();
      await pool.query("REVOKE ALL ON mr_spend FROM mr_t23_upd");
    }
    // app finalize: cannot release once a txId is pinned; can mark ambiguous/settled
    expect(await s.finalize("a", "released", Date.now())).toBe(false);
    expect(await s.finalize("a", "ambiguous", Date.now(), "TXOTHER")).toBe(true);
    expect(await s.get("a")).toMatchObject({ status: "ambiguous", txId: "TXA" }); // pinned tx kept
    // an un-pinned release by the app is audited
    await s.reserve({ id: "b", payer: "P", amountMicro: 1n, caps, nowMs: Date.now() });
    expect(await s.finalize("b", "released", Date.now())).toBe(true);
    expect(await spendAudit(pool, store, "b")).toMatchObject([{ action: "app-release-unbroadcast", to_status: "released" }]);
  });

  it("R23-P3-1: role SQL limits app roles; mr_demo_api writes status only via mr_spend_app_finalize", async () => {
    const { stdout } = await applyRoles();
    expect(stdout).not.toMatch(/t-(rec|mon|rel)-pw/);
    expect(stdout).toMatch(/mr_spend_app_finalize\(text,text,text,text\)/);
    expect(stdout).toMatch(/search_path=pg_catalog, pg_temp/);
    expect(stdout).toMatch(/mr_demo_api.*mr_spend.*tx_id/s);
    const pool = await getPool();
    await pool.query("ALTER ROLE mr_demo_api LOGIN PASSWORD 't-app-pw'");
    const app = poolAs("mr_demo_api", "t-app-pw");
    const store = uid("app");
    try {
      const s = new PgSpendStore(app, { store });
      expect((await s.reserve({ id: "a", payer: "P", amountMicro: 1n, caps, nowMs: Date.now() })).ok).toBe(true);
      expect(await s.attachTxId("a", "TXA", Date.now(), 100)).toBe(true);
      await expect(app.query("UPDATE mr_spend SET status = 'released' WHERE store = $1", [store])).rejects.toThrow(/permission/);
      await expect(app.query("SELECT * FROM mr_spend_release($1,'a','manual-release-forced','x','long enough reason',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)", [store])).rejects.toThrow(/permission/);
      await expect(app.query("SELECT * FROM mr_spend_settle($1,'a',ARRAY['pending'],'settled','chain-reconcile','x','y','TXA')", [store])).rejects.toThrow(/permission/);
      await expect(app.query("INSERT INTO mr_spend_audit (store, id, at_ms, actor, action, from_status, to_status, reason) VALUES ($1,'a',1,'x','y','pending','released','z')", [store])).rejects.toThrow(/permission/);
      expect(await s.finalize("a", "settled", Date.now(), "TXA")).toBe(true);
      for (const r of ["mr_console", "mr_bridge"]) {
        const { rows } = await pool.query("SELECT has_table_privilege($1, 'mr_spend', 'SELECT') AS sel, has_function_privilege($1, 'mr_spend_app_finalize(text,text,text,text)', 'EXECUTE') AS fin", [r]);
        expect(rows[0]).toEqual({ sel: false, fin: false });
      }
    } finally {
      await app.end();
      await pool.query("ALTER ROLE mr_demo_api NOLOGIN PASSWORD NULL");
    }
  });

  it("R23-P3-3: settle requires a pinned, non-null txId matching the row", async () => {
    await applyRoles();
    const pool = await getPool();
    const store = uid("set");
    const s = new PgSpendStore(pool, { store });
    await pinnedAmbiguous(s, "a", "TXA", 100);
    await pinnedAmbiguous(s, "n", null, null);
    const rec = poolAs("mr_reconcile", "t-rec-pw");
    try {
      const st = (id: string, tx: string | null) => rec.query("SELECT * FROM mr_spend_settle($1,$2,ARRAY['ambiguous'],'settled','chain-reconcile','r','confirmed',$3)", [store, id, tx]);
      await expect(st("a", null)).rejects.toThrow(/pinned, non-null txId/);
      expect((await st("n", "TXANY")).rows[0]).toEqual({ ok: false, from_status: "ambiguous" });
      expect((await st("a", "TXB")).rows[0]).toEqual({ ok: false, from_status: "ambiguous" });
      expect((await st("a", "TXA")).rows[0]).toEqual({ ok: true, from_status: "ambiguous" });
      // reconcile never settles a row without a txId, even if the check says "settled"
      expect(await reconcileSpendPg(rec, { store, check: async () => "settled" })).toMatchObject({ checked: 1, settled: 0, unknown: 1 });
      expect((await s.get("n"))!.status).toBe("ambiguous");
    } finally {
      await rec.end();
    }
  });

  it("R23-P3-4: needsRelease rows flagged longer than the limit are counted and alert", async () => {
    await applyRoles();
    const pool = await getPool();
    const store = uid("nr");
    const s = new PgSpendStore(pool, { store });
    await s.reserve({ id: "a", payer: "P", amountMicro: 1n, caps, nowMs: Date.now() - 3_600_000 });
    await s.attachTxId("a", "TXA", Date.now(), 100);
    const rec = poolAs("mr_reconcile", "t-rec-pw");
    try {
      expect(await reconcileSpendPg(rec, { store, check: async () => "released" })).toMatchObject({ needsRelease: 1 });
    } finally {
      await rec.end();
    }
    const now = Date.now();
    expect(await staleSpendCounts(pool, { store, olderThanMs: 30 * 60_000, needsReleaseOlderThanMs: 60 * 60_000, nowMs: now })).toMatchObject({ ambiguous: 1, needsReleaseOverdue: 0 });
    const later = await staleSpendCounts(pool, { store, olderThanMs: 30 * 60_000, needsReleaseOlderThanMs: 60 * 60_000, nowMs: now + 61 * 60_000 });
    expect(later.needsReleaseOverdue).toBe(1);
    expect(later.needsReleaseOldestAgeMs).toBeGreaterThanOrEqual(60 * 60_000);
    const ok = (async () => new Response("{}", { status: 200 })) as unknown as typeof fetch;
    const r = await runMonitor({ env: { MONITOR_HEALTH_URLS: "http://h/health" }, store, olderThanMin: 30, stale: async () => ({ pending: 0, ambiguous: 0, oldestAgeMs: null, needsReleaseOverdue: 1, needsReleaseOldestAgeMs: 61 * 60_000 }), fetchImpl: ok, err: () => undefined, log: () => undefined });
    expect(r.exitCode).toBe(2);
    expect(r.reasons.join(" ")).toMatch(/needsRelease overdue: 1 .* more than 60 min/);
    await expect(runMonitor({ env: { MONITOR_HEALTH_URLS: "http://h/health", MONITOR_NEEDS_RELEASE_MAX_MIN: "0" }, store, olderThanMin: 30, stale: async () => later, fetchImpl: ok })).rejects.toThrow(MonitorConfigError);
    const r2 = await runMonitor({ env: { MONITOR_HEALTH_URLS: "http://h/health", MONITOR_NEEDS_RELEASE_MAX_MIN: "90" }, store, olderThanMin: 30, stale: async () => ({ ...later, ambiguous: 0, needsReleaseOverdue: 1 }), fetchImpl: ok, err: () => undefined, log: () => undefined });
    expect(r2.reasons.join(" ")).toMatch(/more than 90 min/);
  });

  it("R23: `spend release --password-stdin` takes the mr_release password at runtime (env file holds none); never printed", async () => {
    await applyRoles();
    const pool = await getPool();
    const store = uid("cli");
    const s = new PgSpendStore(pool, { store });
    await pinnedAmbiguous(s, "n", null, null);
    const u = new URL(PG_URL!);
    u.username = "mr_release";
    u.password = "";
    const dir = mkdtempSync(path.join(tmpdir(), "mr-rel-"));
    const envFile = path.join(dir, "state-release.env");
    writeFileSync(envFile, `DATABASE_URL=${u.toString()}\nNETWORK=testnet\n`);
    const tsx = path.resolve(__dirname, "../node_modules/.bin/tsx");
    const cli = path.resolve(__dirname, "spend-cli.ts");
    const env = { ...process.env, STATE_ENV_FILE: envFile } as NodeJS.ProcessEnv;
    delete env.DATABASE_URL;
    delete env.PGPASSWORD;
    const go = (stdin: string, extra: string[] = []) =>
      new Promise<{ code: number | null; out: string }>((resolve) => {
        const c = spawn(tsx, [cli, "release", "--store", store, "--id", "n", "--operator", "david", "--reason", "cli stdin check", "--force", "--password-stdin", ...extra], { env });
        let out = "";
        c.stdout.on("data", (d) => (out += d));
        c.stderr.on("data", (d) => (out += d));
        c.on("close", (code) => resolve({ code, out }));
        c.stdin.end(stdin);
      });
    const empty = await go("");
    expect(empty.code).toBe(1);
    expect(empty.out).toMatch(/empty password on stdin/);
    const ok = await go("t-rel-pw\n");
    expect(ok.code).toBe(0);
    expect(ok.out).toMatch(/"to":"released"/);
    expect(ok.out).not.toMatch(/t-rel-pw/);
    expect((await s.get("n"))!.status).toBe("released");
    // a URL that already carries a password is refused with --password-stdin (and not echoed)
    u.password = "inurl-pw";
    writeFileSync(envFile, `DATABASE_URL=${u.toString()}\nNETWORK=testnet\n`);
    const dup = await go("t-rel-pw\n");
    expect(dup.code).toBe(1);
    expect(dup.out).toMatch(/must not contain a password/);
    expect(dup.out).not.toMatch(/inurl-pw|t-rel-pw/);
  });
});

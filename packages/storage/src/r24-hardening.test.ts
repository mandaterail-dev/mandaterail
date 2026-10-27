/**
 * R24 (internal reviewer run 24) on real Postgres:
 *  - R24-P2-1: mr_spend_release needs two independent observations (different
 *    providers, >= 1 indexer, each genesis = marker, round > lv + margin, 404).
 *  - R24-P3-1: owner NOLOGIN, migrate as mr_admin via SET ROLE; role SQL RAISEs
 *    on a disabled trigger and prints tgenabled + the marker.
 *  - R24-P3-2: app INSERTs only pending / NULL tx_id, last_valid / created_ms
 *    within +-5 min; finalize-to-released ignores p_tx_id.
 *  - R24-P3-3: mainnet marker needs allowMainnet; the chain is verified first.
 *  - R24-P3-4: app roles NOINHERIT.
 */
import { afterAll, describe, expect, it } from "vitest";
import { execFile } from "node:child_process";
import path from "node:path";
import { promisify } from "node:util";
import pg from "pg";
import { TESTNET_PROFILE, toMicro } from "@mandaterail/core";
import { migratePostgres, PgSpendStore, PG_SCHEMA_VERSION } from "./pg.js";
import { spendAudit } from "./spend-ops.js";
import { closeShared, getPool, PG_URL, uid } from "./test-helpers.js";

afterAll(closeShared);
const run = promisify(execFile);
const SQL = path.resolve(__dirname, "../../../deploy/sql/t11-mr-reconcile-role.sql");
const WIN = path.resolve(__dirname, "../../../deploy/sql/r25-admin-window.sql");
const caps = { perPaymentMicro: toMicro("1"), perDayMicro: toMicro("5") };
const pwArgs = ["-v", "pw=t-rec-pw", "-v", "mon_pw=t-mon-pw", "-v", "rel_pw=t-rel-pw"];
const applyRoles = (url = PG_URL!, extra: string[] = []) => run("psql", ["-X", "-q", "-v", "ON_ERROR_STOP=1", ...pwArgs, ...extra, "-d", url, "-f", SQL]);
const TN = TESTNET_PROFILE.caip2.slice(9);
const okVerify = async (p: { caip2: string }) => ({ genesisHash: p.caip2.slice(9) });
function poolAs(role: string, pw: string, base = PG_URL!): pg.Pool {
  const u = new URL(base);
  u.username = role;
  u.password = pw;
  const p = new pg.Pool({ connectionString: u.toString(), max: 2 });
  p.on("error", () => undefined);
  return p;
}
const dbUrl = (db: string) => PG_URL!.replace(/\/[^/]*$/, `/${db}`);
// 18-arg release: tx, lv, margin, then (provider, kind, genesis, round, status) x 2
const REL = "SELECT * FROM mr_spend_release($1,$2,'manual-release','david','operator check',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)";
type Obs = [string | null, string | null, string | null, number | null, number | null];
const good = (p: string, kind = "indexer", round = 1500): Obs => [p, kind, TN, round, 404];

describe.skipIf(!PG_URL)("R24 hardening [postgres]", () => {
  it("R24-P2-1: the DB requires two complete, independent, genesis-checked observations", async () => {
    await applyRoles();
    const pool = await getPool();
    const store = uid("r24");
    const s = new PgSpendStore(pool, { store });
    await s.reserve({ id: "g", payer: "P", amountMicro: 1n, caps, nowMs: Date.now() });
    await s.attachTxId("g", "TXG", Date.now(), 900);
    await s.finalize("g", "ambiguous", Date.now());
    const rel = poolAs("mr_release", "t-rel-pw");
    try {
      const q = (o1: Obs, o2: Obs, lv = 900, m = 10) => rel.query(REL, [store, "g", "TXG", lv, m, ...o1, ...o2]);
      const none: Obs = [null, null, null, null, null];
      await expect(q(good("idx-a.example"), none)).rejects.toThrow(/observation 2 is incomplete/);
      await expect(q(good("idx-a.example"), good("idx-a.example"))).rejects.toThrow(/different operators \(both are test-op-a\)/);
      await expect(q(good("algod-a.example", "algod"), good("algod-b.example", "algod"))).rejects.toThrow(/at least one observation must come from an indexer/);
      await expect(q(good("idx-a.example"), good("idx-b.example", "indexer", 910))).rejects.toThrow(/observation 2 round 910 is not past/);
      await expect(q(good("idx-a.example"), ["idx-b.example", "indexer", "wrong-genesis", 1500, 404])).rejects.toThrow(/observation 2 genesis/);
      await expect(q(good("idx-a.example"), ["idx-b.example", "indexer", TN, 1500, 200])).rejects.toThrow(/observation 2 must show .*404/);
      await expect(q(good("idx-a.example"), ["idx_b.example", "indexer", TN, 1500, 404])).rejects.toThrow(/must be a host\[:port\]/); // R26-P3-4: case is normalized now; malformed hosts still refused
      await expect(q(good("idx-a.example"), ["idx-b.example", "explorer", TN, 1500, 404])).rejects.toThrow(/kind must be/);
      await expect(q(good("idx-a.example", "indexer", 9999999999), good("idx-b.example"), 900, -1)).rejects.toThrow(/margin must be >= 0/);
      expect((await s.get("g"))!.status).toBe("ambiguous");
      expect((await q(good("idx-a.example"), good("algod-b.example:8443", "algod", 1600))).rows[0]).toEqual({ ok: true, from_status: "ambiguous" });
      expect((await spendAudit(pool, store, "g"))[0]).toMatchObject({
        proof_provider: "idx-a.example", proof_kind: "indexer", proof_round_checked: "1500", proof_indexer_status: 404,
        proof2_provider: "algod-b.example:8443", proof2_kind: "algod", proof2_genesis_hash: TN, proof2_round_checked: "1600", proof2_status: 404,
      });
    } finally {
      await rel.end();
    }
  });

  it("R24-P3-2: app inserts are pending-only, unpinned and near the DB clock; released ignores p_tx_id", async () => {
    await applyRoles();
    const pool = await getPool();
    await pool.query("ALTER ROLE mr_demo_api LOGIN PASSWORD 't-app-pw'");
    const app = poolAs("mr_demo_api", "t-app-pw");
    const store = uid("ins");
    const ins = (id: string, status: string, created: number, tx: string | null, lv: number | null) =>
      app.query("INSERT INTO mr_spend (store, id, payer, amount_micro, status, created_ms, updated_ms, tx_id, last_valid) VALUES ($1,$2,'P',1,$3,$4,$4,$5,$6)", [store, id, status, created, tx, lv]);
    try {
      const now = Date.now();
      await expect(ins("a", "settled", now, null, null)).rejects.toThrow(/only be pending/);
      await expect(ins("b", "released", now, null, null)).rejects.toThrow(/only be pending/);
      await expect(ins("c", "pending", now, "TXC", null)).rejects.toThrow(/NULL tx_id and last_valid/);
      await expect(ins("d", "pending", now, null, 100)).rejects.toThrow(/NULL tx_id and last_valid/);
      await expect(ins("e", "pending", now - 3_600_000, null, null)).rejects.toThrow(/within 5 minutes/);
      await expect(ins("f", "pending", now + 600_000, null, null)).rejects.toThrow(/within 5 minutes/);
      await ins("ok", "pending", now - 60_000, null, null);
      const s = new PgSpendStore(app, { store });
      // the app's settled-import path no longer works as the app role
      await expect(s.recordSettled({ id: "imp", payer: "P", amountMicro: 1n, createdMs: now })).rejects.toThrow(/only be pending/);
      expect(await s.finalize("ok", "released", now, "TXFORGED")).toBe(true);
      expect(await s.get("ok")).toMatchObject({ status: "released", txId: null });
      expect((await s.reserve({ id: "r", payer: "P", amountMicro: 1n, caps, nowMs: Date.now() })).ok).toBe(true);
      expect(await s.finalize("r", "settled", now, "TXR")).toBe(true); // settle may still fill an unpinned txId
      expect((await s.get("r"))!.txId).toBe("TXR");
    } finally {
      await app.end();
      await pool.query("ALTER ROLE mr_demo_api NOLOGIN PASSWORD NULL");
    }
  });

  it("R24-P3-3: mainnet needs allowMainnet; the chain is verified before the marker is written", async () => {
    const admin = await getPool();
    const db = `mr_r24_${uid("n").replace(/-/g, "_")}`;
    await admin.query(`CREATE DATABASE ${db}`);
    const p = new pg.Pool({ connectionString: dbUrl(db), max: 2 });
    p.on("error", () => undefined);
    try {
      await expect(migratePostgres(p, { network: "mainnet", allowMainnet: false, verifyNetwork: okVerify })).rejects.toThrow(/ALLOW_MAINNET=1/);
      await expect(migratePostgres(p, { network: "testnet", verifyNetwork: async () => { throw new Error("algod unreachable (/versions)"); } })).rejects.toThrow(/network check failed .*algod unreachable/);
      await expect(migratePostgres(p, { network: "testnet", verifyNetwork: async () => ({ genesisHash: "wrong" }) })).rejects.toThrow(/marker not written/);
      // all-or-nothing: nothing was applied by the failed runs
      expect((await p.query("SELECT to_regclass('mr_network') AS t")).rows[0].t).toBeNull();
      let seen = "";
      expect(await migratePostgres(p, { network: "testnet", verifyNetwork: async (prof) => { seen = prof.name; return okVerify(prof); } })).toMatchObject({ network: "testnet" });
      expect(seen).toBe("testnet");
    } finally {
      await p.end();
      await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`);
    }
  });

  it("R24-P3-1 / R24-P3-4: owner NOLOGIN, migrate as mr_admin via SET ROLE, triggers checked, app roles NOINHERIT", async () => {
    const admin = await getPool();
    const db = `mr_r24_${uid("o").replace(/-/g, "_")}`;
    await admin.query("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mr_owner') THEN CREATE ROLE mr_owner; END IF; END $$");
    await admin.query("ALTER ROLE mr_owner LOGIN PASSWORD 't-own-pw' NOSUPERUSER");
    await admin.query(`CREATE DATABASE ${db} OWNER mr_owner`);
    const url = dbUrl(db);
    const own = poolAs("mr_owner", "t-own-pw", url);
    try {
      // the pre-R24 state: the owner logs in and migrates
      expect(await migratePostgres(own, { network: "testnet", verifyNetwork: okVerify })).toMatchObject({ to: PG_SCHEMA_VERSION });
      await own.end();
      const { stdout } = await applyRoles(url, ["-v", "admin_pw=t-adm-pw"]);
      expect(stdout).not.toMatch(/t-(rec|mon|rel|adm)-pw/);
      expect(stdout).toMatch(/mr_spend_guard_row\s*\|\s*O/);
      expect(stdout).toMatch(/testnet\s*\|\s*\S+/);
      const roles = await admin.query("SELECT rolname, rolcanlogin, rolinherit FROM pg_roles WHERE rolname IN ('mr_owner','mr_admin','mr_demo_api','mr_console','mr_bridge') ORDER BY 1");
      expect(roles.rows).toEqual([
        { rolname: "mr_admin", rolcanlogin: true, rolinherit: false },
        { rolname: "mr_bridge", rolcanlogin: false, rolinherit: false },
        { rolname: "mr_console", rolcanlogin: false, rolinherit: false },
        { rolname: "mr_demo_api", rolcanlogin: false, rolinherit: false },
        { rolname: "mr_owner", rolcanlogin: false, rolinherit: true },
      ]);
      const own2 = poolAs("mr_owner", "t-own-pw", url);
      await expect(own2.query("SELECT 1")).rejects.toThrow(/not permitted to log in/);
      await own2.end();
      const adm = poolAs("mr_admin", "t-adm-pw", url);
      try {
        // without SET ROLE the admin has none of the owner's rights (NOINHERIT membership)
        await expect(adm.query("ALTER TABLE mr_spend DISABLE TRIGGER mr_spend_guard_row")).rejects.toThrow(/must be owner/);
        await expect(adm.query("SELECT count(*) FROM mr_spend")).rejects.toThrow(/permission denied/);
        await expect(migratePostgres(adm, { network: "testnet", verifyNetwork: okVerify })).rejects.toThrow(/permission denied|must be owner/);
        // R25-P3-1: outside a deploy window mr_admin cannot become the owner at all
        await expect(migratePostgres(adm, { network: "testnet", setRole: "mr_owner", verifyNetwork: okVerify })).rejects.toThrow(/permission denied to set role/);
        // R26-P3-1: open needs a window-lock holder (normally deploy/mr-admin-window.sh)
        const lk = new pg.Client({ connectionString: url });
        await lk.connect();
        await lk.query("SET application_name = 'mr-admin-window'"); // R27-P3-2: only the window's own session may hold it
        await lk.query("SELECT pg_advisory_lock(26026, 1)");
        await run("psql", ["-X", "-q", "-v", "ON_ERROR_STOP=1", "-v", "window=open", "-d", url, "-f", WIN]);
        await lk.end();
        expect(await migratePostgres(adm, { network: "testnet", setRole: "mr_owner", verifyNetwork: okVerify })).toEqual({ from: PG_SCHEMA_VERSION, to: PG_SCHEMA_VERSION, network: "testnet", role: "mr_owner" });
        await expect(migratePostgres(adm, { network: "testnet", setRole: "mr_owner; DROP TABLE x", verifyNetwork: okVerify })).rejects.toThrow(/plain role name/);
        await run("psql", ["-X", "-q", "-v", "ON_ERROR_STOP=1", "-v", "window=close", "-d", url, "-f", WIN]);
        await expect(migratePostgres(adm, { network: "testnet", setRole: "mr_owner", verifyNetwork: okVerify })).rejects.toThrow(/permission denied to set role/);
      } finally {
        await adm.end();
      }
      // a disabled trigger fails the role SQL (and with it the deploy evidence step)
      await admin.query(`SELECT 1`);
      const sup = new pg.Pool({ connectionString: url, max: 1 });
      sup.on("error", () => undefined);
      try {
        await sup.query("ALTER TABLE mr_spend DISABLE TRIGGER mr_spend_guard_row");
        await expect(applyRoles(url)).rejects.toThrow(/mr_spend\.mr_spend_guard_row is missing or not enabled/);
        await sup.query("ALTER TABLE mr_spend ENABLE TRIGGER mr_spend_guard_row");
        // an app role switched back to INHERIT is fixed by a re-run (always re-applied)
        await sup.query("ALTER ROLE mr_console INHERIT");
        await applyRoles(url);
        expect((await sup.query("SELECT rolinherit FROM pg_roles WHERE rolname = 'mr_console'")).rows[0].rolinherit).toBe(false);
      } finally {
        await sup.end();
      }
    } finally {
      await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`);
      await admin.query("DROP OWNED BY mr_admin CASCADE").catch(() => undefined);
      await admin.query("DROP ROLE IF EXISTS mr_admin");
      await admin.query("DROP ROLE IF EXISTS mr_owner");
    }
  });
});

/**
 * R21-P3-2 / R21-P3-3 / R21-P3-5 on real Postgres: the role SQL in
 * deploy/sql/t11-mr-reconcile-role.sql, the SECURITY DEFINER transition
 * function, the read-only monitor role, and network-aware no-proof errors.
 */
import { afterAll, describe, expect, it } from "vitest";
import { execFile } from "node:child_process";
import path from "node:path";
import { promisify } from "node:util";
import pg from "pg";
import { toMicro } from "@mandaterail/core";
import { PgSpendStore, schemaVersions } from "./pg.js";
import { releaseSpendManually, spendAudit, staleSpendCounts } from "./spend-ops.js";
import { closeShared, getPool, PG_URL, uid } from "./test-helpers.js";

afterAll(closeShared);
const run = promisify(execFile);
const SQL = path.resolve(__dirname, "../../../deploy/sql/t11-mr-reconcile-role.sql");
const caps = { perPaymentMicro: toMicro("1"), perDayMicro: toMicro("5") };
const FN = "mr_spend_settle(text, text, text[], text, text, text, text, text)"; // v6 (R22-P3-1) replaced mr_spend_transition
const REL = "mr_spend_release(text, text, text, text, text, text, bigint, integer, text, text, text, bigint, integer, text, text, text, bigint, integer)";

const applyRoles = () => run("psql", ["-X", "-q", "-v", "ON_ERROR_STOP=1", "-v", "pw=t-rec-pw", "-v", "mon_pw=t-mon-pw", "-v", "rel_pw=t-rel-pw", "-d", PG_URL!, "-f", SQL]);
function poolAs(role: string, pw: string): pg.Pool {
  const u = new URL(PG_URL!);
  u.username = role;
  u.password = pw;
  const p = new pg.Pool({ connectionString: u.toString(), max: 1 });
  p.on("error", () => undefined);
  return p;
}
async function flags(pool: pg.Pool, r: string) {
  const { rows } = await pool.query(
    `SELECT rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, rolinherit, rolconnlimit,
            (SELECT count(*)::int FROM pg_auth_members am WHERE am.member = r.oid) AS memberships
       FROM pg_roles r WHERE rolname = $1`, [r]);
  return rows[0];
}

describe.skipIf(!PG_URL)("R21 roles + definer function [postgres]", () => {
  it("v6 migration: settle/release are SECURITY DEFINER, fixed search_path, no PUBLIC execute; v5 function dropped", async () => {
    const pool = await getPool();
    expect(await schemaVersions(pool)).toEqual(expect.arrayContaining([5, 6]));
    for (const [name, sig] of [["mr_spend_settle", FN], ["mr_spend_release", REL]] as const) {
      const { rows } = await pool.query(`SELECT prosecdef, proconfig, has_function_privilege('public', $1, 'EXECUTE') AS pub FROM pg_proc WHERE proname = $2`, [sig, name]);
      expect(rows[0]).toMatchObject({ prosecdef: true, pub: false });
      expect(rows[0].proconfig).toEqual(["search_path=pg_catalog, pg_temp"]);
    }
    expect((await pool.query("SELECT 1 FROM pg_proc WHERE proname = 'mr_spend_transition'")).rowCount).toBe(0);
  });

  it("R21-P3-2/3: role SQL applies; mr_reconcile writes only through the function; mr_monitor is read-only", async () => {
    const pool = await getPool();
    const { stdout } = await applyRoles();
    expect(stdout).toMatch(/mr_monitor/);
    expect(stdout).not.toMatch(/t-rec-pw|t-mon-pw/);
    for (const r of ["mr_reconcile", "mr_monitor"]) {
      // R28-P3-2: no memberships at all (pg_read_all_stats revoked)
      expect(await flags(pool, r)).toMatchObject({ rolsuper: false, rolcreaterole: false, rolcreatedb: false, rolbypassrls: false, rolinherit: false, memberships: 0 });
    }
    const store = uid("r21");
    const s = new PgSpendStore(pool, { store });
    await s.reserve({ id: "a", payer: "P", amountMicro: 1n, caps, nowMs: Date.now() - 3_600_000 });
    await s.finalize("a", "ambiguous", Date.now());
    const rec = poolAs("mr_reconcile", "t-rec-pw");
    const mon = poolAs("mr_monitor", "t-mon-pw");
    try {
      await expect(rec.query("UPDATE mr_spend SET payer = 'EVIL' WHERE store = $1", [store])).rejects.toThrow(/permission/);
      await expect(rec.query("UPDATE mr_spend SET status = 'released' WHERE store = $1", [store])).rejects.toThrow(/permission/);
      await expect(rec.query("INSERT INTO mr_spend_audit (store, id, at_ms, actor, action, from_status, to_status, reason) VALUES ($1,'a',1,'x','forged','pending','released','x')", [store])).rejects.toThrow(/permission/);
      // the settle function only allows whitelisted targets/sources/actions
      await expect(rec.query(`SELECT * FROM mr_spend_settle($1,'a',ARRAY['ambiguous'],'pending','chain-reconcile','x','z',NULL)`, [store])).rejects.toThrow(/not allowed/);
      await expect(rec.query(`SELECT * FROM mr_spend_settle($1,'a',ARRAY['settled'],'settled','chain-reconcile','x','z',NULL)`, [store])).rejects.toThrow(/source statuses/);
      await expect(rec.query(`SELECT * FROM mr_spend_settle($1,'a',ARRAY['ambiguous'],'settled','chain-reconcile','x','',NULL)`, [store])).rejects.toThrow(/required/);
      // R22-P3-1: mr_reconcile can never release, via the library or the function
      await expect(releaseSpendManually(rec, { store, id: "a", operator: "t", reason: "r21 role check", force: true, network: "testnet", warn: () => undefined })).rejects.toThrow(/cannot release.*mr_release/);
      expect(await s.get("a")).toMatchObject({ status: "ambiguous", payer: "P" });
      // mr_release: status change + audit row together
      const relp = poolAs("mr_release", "t-rel-pw");
      try {
        expect(await releaseSpendManually(relp, { store, id: "a", operator: "t", reason: "r21 role check", force: true, network: "testnet", warn: () => undefined })).toMatchObject({ to: "released", forced: true });
      } finally {
        await relp.end();
      }
      expect(await s.get("a")).toMatchObject({ status: "released", payer: "P" });
      expect(await spendAudit(pool, store, "a")).toMatchObject([{ actor: "mr_release (label, untrusted: t)", action: "manual-release-forced", from_status: "ambiguous", to_status: "released" }]);
      // monitor: reads only
      expect(await staleSpendCounts(mon, { store, olderThanMs: 60_000 })).toMatchObject({ pending: 0, ambiguous: 0 });
      await expect(mon.query("UPDATE mr_spend SET status = 'released' WHERE store = $1", [store])).rejects.toThrow(/permission/);
      await expect(mon.query(`SELECT * FROM mr_spend_settle($1,'a',ARRAY['ambiguous'],'settled','chain-reconcile','x','z',NULL)`, [store])).rejects.toThrow(/permission/);
      await expect(mon.query(`SELECT * FROM mr_spend_release($1,'a','manual-release-forced','x','zzzzzzzzz',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)`, [store])).rejects.toThrow(/permission/);
      await expect(mon.query("INSERT INTO mr_spend_audit (store, id, at_ms, actor, action, from_status, to_status, reason) VALUES ($1,'a',1,'x','f','p','r','x')", [store])).rejects.toThrow(/permission/);
    } finally {
      await rec.end();
      await mon.end();
    }
  });

  it("R21-P3-3: re-running resets drifted flags, memberships and grants (idempotent)", async () => {
    const pool = await getPool();
    await applyRoles();
    await pool.query("ALTER ROLE mr_reconcile CREATEDB CREATEROLE INHERIT CONNECTION LIMIT -1");
    await pool.query("GRANT pg_read_all_data TO mr_reconcile");
    await pool.query("GRANT mr_reconcile TO mr_monitor");
    await pool.query("GRANT UPDATE ON mr_spend TO mr_reconcile; GRANT UPDATE (status) ON mr_spend TO mr_monitor; GRANT INSERT ON mr_spend_audit TO mr_reconcile");
    await applyRoles();
    await applyRoles(); // twice: still fine
    expect(await flags(pool, "mr_reconcile")).toMatchObject({ rolcreatedb: false, rolcreaterole: false, rolinherit: false, rolconnlimit: 4, memberships: 0 });
    expect(await flags(pool, "mr_monitor")).toMatchObject({ rolconnlimit: 2, memberships: 0 }); // R28-P3-2: no pg_read_all_stats
    const { rows } = await pool.query(`SELECT has_table_privilege('mr_reconcile','mr_spend','UPDATE') AS u, has_table_privilege('mr_reconcile','mr_spend_audit','INSERT') AS i, has_any_column_privilege('mr_monitor','mr_spend','UPDATE') AS c`);
    expect(rows[0]).toEqual({ u: false, i: false, c: false });
  });

  it("R21-P3-3: RAISEs (and rolls back) if a service role owns the audit table", async () => {
    const pool = await getPool();
    await applyRoles();
    const { rows } = await pool.query<{ o: string }>("SELECT tableowner AS o FROM pg_tables WHERE schemaname='public' AND tablename='mr_spend_audit'");
    const owner = rows[0]!.o;
    await pool.query("ALTER TABLE mr_spend_audit OWNER TO mr_reconcile");
    try {
      const e = (await applyRoles().catch((x) => x)) as { code?: number; stderr?: string };
      expect(e.code).not.toBe(0);
      expect(e.stderr).toMatch(/mr_reconcile owns mr_spend_audit/);
      const fo = await pool.query<{ o: string }>("SELECT pg_get_userbyid(proowner) AS o FROM pg_proc WHERE proname = 'mr_spend_settle'");
      expect(fo.rows[0]!.o).not.toBe("mr_reconcile"); // rolled back
    } finally {
      await pool.query(`ALTER TABLE mr_spend_audit OWNER TO "${owner.replace(/"/g, '""')}"`);
    }
    await applyRoles();
  });

  it("R21-P3-5: the no-proof error never suggests --force on MainNet", async () => {
    const pool = await getPool();
    const store = uid("hint");
    const s = new PgSpendStore(pool, { store });
    await s.reserve({ id: "a", payer: "P", amountMicro: 1n, caps, nowMs: Date.now() });
    const prove = async () => ({ ok: false as const, why: "indexer round unknown" });
    const base = { store, id: "a", operator: "d", reason: "hint wording check" };
    const mn = await releaseSpendManually(pool, { ...base, prove, network: "mainnet" }).catch((e: Error) => e.message);
    expect(mn).toMatch(/MainNet has no override/);
    expect(mn).not.toMatch(/--force/);
    const mn2 = await releaseSpendManually(pool, { ...base, network: "mainnet" }).catch((e: Error) => e.message);
    expect(mn2).toMatch(/chain proof required/);
    expect(mn2).not.toMatch(/--force/);
    expect(await releaseSpendManually(pool, { ...base, prove, network: "testnet" }).catch((e: Error) => e.message)).toMatch(/on TestNet you may pass --force/);
  });
});

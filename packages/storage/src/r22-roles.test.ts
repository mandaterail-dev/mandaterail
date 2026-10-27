/**
 * R22-P3-1 / R22-P3-2 / R22-P3-3 / R22-P3-4 on real Postgres: settle/release
 * split with DB-side timestamp + session_user + action whitelist, TEMPORARY
 * revoked from PUBLIC, monitor self-failure via the CLI, passwordless roles.
 */
import { afterAll, describe, expect, it } from "vitest";
import { execFile } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import pg from "pg";
import { toMicro } from "@mandaterail/core";
import { PgSpendStore } from "./pg.js";
import { spendAudit } from "./spend-ops.js";
import { closeShared, getPool, PG_URL, uid } from "./test-helpers.js";

afterAll(closeShared);
const run = promisify(execFile);
const SQL = path.resolve(__dirname, "../../../deploy/sql/t11-mr-reconcile-role.sql");
const caps = { perPaymentMicro: toMicro("1"), perDayMicro: toMicro("5") };
const pwArgs = ["-v", "pw=t-rec-pw", "-v", "mon_pw=t-mon-pw", "-v", "rel_pw=t-rel-pw"];
const applyRoles = (extra: string[] = pwArgs) => run("psql", ["-X", "-q", "-v", "ON_ERROR_STOP=1", ...extra, "-d", PG_URL!, "-f", SQL]);
function poolAs(role: string, pw: string): pg.Pool {
  const u = new URL(PG_URL!);
  u.username = role;
  u.password = pw;
  const p = new pg.Pool({ connectionString: u.toString(), max: 1 });
  p.on("error", () => undefined);
  return p;
}
async function ambiguousRow(store: string, id: string, txId?: string) {
  const s = new PgSpendStore(await getPool(), { store });
  await s.reserve({ id, payer: "P", amountMicro: 1n, caps, nowMs: Date.now() - 3_600_000 });
  if (txId) await s.attachTxId(id, txId, Date.now(), 100);
  await s.finalize(id, "ambiguous", Date.now());
  return s;
}

describe.skipIf(!PG_URL)("R22 settle/release split + role SQL [postgres]", () => {
  it("R22-P3-1: mr_reconcile can settle but never release; DB sets time + session_user; actions whitelisted", async () => {
    await applyRoles();
    const pool = await getPool();
    const store = uid("r22");
    const s = await ambiguousRow(store, "a", "TXA");
    await ambiguousRow(store, "b");
    const rec = poolAs("mr_reconcile", "t-rec-pw");
    const rel = poolAs("mr_release", "t-rel-pw");
    try {
      // reconcile: no release function, no release target, no foreign actions
      await expect(rec.query(`SELECT * FROM mr_spend_release($1,'a','manual-release-forced','x','long enough reason',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)`, [store])).rejects.toThrow(/permission/);
      await expect(rec.query(`SELECT * FROM mr_spend_settle($1,'a',ARRAY['ambiguous'],'released','chain-reconcile','x','z',NULL)`, [store])).rejects.toThrow(/not allowed/);
      await expect(rec.query(`SELECT * FROM mr_spend_settle($1,'a',ARRAY['ambiguous'],'settled','manual-release','x','z',NULL)`, [store])).rejects.toThrow(/action .* not allowed/);
      await expect(rec.query(`SELECT * FROM mr_spend_settle($1,'a',ARRAY['ambiguous'],'ambiguous','chain-reconcile-expired','x','z',NULL)`, [store])).rejects.toThrow(/source statuses/);
      // old catch-all with caller-chosen timestamp is gone
      await expect(rec.query(`SELECT * FROM mr_spend_transition($1,'a',ARRAY['ambiguous'],'released','x','y','z',1,NULL,false)`, [store])).rejects.toThrow(/does not exist/);
      // settle: timestamp from the DB clock, actor from session_user, label kept as untrusted
      const t0 = Date.now();
      const r = await rec.query(`SELECT * FROM mr_spend_settle($1,'a',ARRAY['ambiguous'],'settled','chain-reconcile','operator:forged','confirmed','TXA')`, [store]);
      expect(r.rows[0]).toMatchObject({ ok: true, from_status: "ambiguous" });
      const [audit] = await spendAudit(pool, store, "a");
      expect(audit).toMatchObject({ actor: "mr_reconcile (label, untrusted: operator:forged)", action: "chain-reconcile", to_status: "settled" });
      expect(Math.abs(Number(audit!.at_ms) - t0)).toBeLessThan(10_000);
      expect((await s.get("a"))!.status).toBe("settled");
      // release: only mr_release, whitelisted actions, proof required for manual-release
      await expect(rel.query(`SELECT * FROM mr_spend_settle($1,'b',ARRAY['ambiguous'],'settled','chain-reconcile','x','z',NULL)`, [store])).rejects.toThrow(/permission/);
      await expect(rel.query(`SELECT * FROM mr_spend_release($1,'b','chain-reconcile','x','long enough reason',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)`, [store])).rejects.toThrow(/action .* not allowed/);
      await expect(rel.query(`SELECT * FROM mr_spend_release($1,'b','manual-release','x','long enough reason',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)`, [store])).rejects.toThrow(/needs txId/);
      await expect(rel.query(`SELECT * FROM mr_spend_release($1,'b','manual-release-forced','','long enough reason',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)`, [store])).rejects.toThrow(/label/);
      const ok = await rel.query(`SELECT * FROM mr_spend_release($1,'b','manual-release-forced','david','FORCED: long enough reason',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)`, [store]);
      expect(ok.rows[0]).toMatchObject({ ok: true });
      expect(await spendAudit(pool, store, "b")).toMatchObject([{ actor: "mr_release (label, untrusted: david)", action: "manual-release-forced", to_status: "released" }]);
      // neither role can backdate: no function takes a timestamp
      const { rows } = await pool.query("SELECT count(*)::int AS n FROM pg_proc WHERE proname IN ('mr_spend_settle','mr_spend_release') AND pg_get_function_arguments(oid) ILIKE '%now%'");
      expect(rows[0].n).toBe(0);
    } finally {
      await rec.end();
      await rel.end();
    }
  });

  it("R22-P3-2: TEMPORARY is revoked from PUBLIC; service roles cannot create temp tables; R66-P3-1: nor the owner (no grant)", async () => {
    const { stdout } = await applyRoles();
    expect(stdout).not.toMatch(/t-(rec|mon|rel)-pw/);
    const pool = await getPool();
    const { rows } = await pool.query(
      `SELECT EXISTS (SELECT 1 FROM aclexplode((SELECT datacl FROM pg_database WHERE datname = current_database())) a WHERE a.grantee = 0 AND a.privilege_type = 'TEMPORARY') AS pub,
              EXISTS (SELECT 1 FROM aclexplode((SELECT datacl FROM pg_database WHERE datname = current_database())) a
                       WHERE a.grantee = (SELECT relowner FROM pg_class WHERE relname = 'mr_spend_audit' AND relnamespace = 'public'::regnamespace) AND a.privilege_type = 'TEMPORARY') AS owner_tmp`,
    );
    expect(rows[0]).toEqual({ pub: false, owner_tmp: false }); // R66-P3-1: the owner has no TEMPORARY grant either
    for (const [role, pw] of [["mr_reconcile", "t-rec-pw"], ["mr_monitor", "t-mon-pw"], ["mr_release", "t-rel-pw"]] as const) {
      const p = poolAs(role, pw);
      try {
        await expect(p.query("CREATE TEMP TABLE t_r22 (x int)")).rejects.toThrow(/permission/);
      } finally {
        await p.end();
      }
    }
  });

  it("R22-P3-4: first run without a password RAISEs and rolls back (role not created as passwordless LOGIN)", async () => {
    const pool = await getPool();
    await pool.query("DROP OWNED BY mr_release; DROP ROLE mr_release");
    const e = (await applyRoles(["-v", "pw=t-rec-pw", "-v", "mon_pw=t-mon-pw"]).catch((x) => x)) as { code?: number; stderr?: string };
    expect(e.code).not.toBe(0);
    expect(e.stderr).toMatch(/mr_release would be LOGIN with no password/);
    expect((await pool.query("SELECT 1 FROM pg_roles WHERE rolname = 'mr_release'")).rowCount).toBe(0); // rolled back
    // a re-run with no passwords at all keeps the existing ones (no error)
    await applyRoles();
    await applyRoles([]);
    const { rows } = await pool.query("SELECT rolname, rolcanlogin, rolpassword IS NOT NULL AS has_pw FROM pg_authid WHERE rolname IN ('mr_reconcile','mr_monitor','mr_release') ORDER BY rolname");
    expect(rows).toEqual([
      { rolname: "mr_monitor", rolcanlogin: true, has_pw: true },
      { rolname: "mr_reconcile", rolcanlogin: true, has_pw: true },
      { rolname: "mr_release", rolcanlogin: true, has_pw: true },
    ]);
  });

  it("R22-P3-3: CLI monitor with the DB unreachable exits 2 (self-failure alert), no secrets printed", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "mr-mon-"));
    const envFile = path.join(dir, "state-monitor.env");
    writeFileSync(envFile, `DATABASE_URL=postgres://mr_monitor:s3cr3tpw@127.0.0.1:1/mandaterail\nNETWORK=testnet\nMONITOR_HEALTH_URLS=http://127.0.0.1:1/health\n`);
    const tsx = path.resolve(__dirname, "../node_modules/.bin/tsx");
    const cli = path.resolve(__dirname, "spend-cli.ts");
    const env = { ...process.env, STATE_ENV_FILE: envFile } as NodeJS.ProcessEnv;
    delete env.DATABASE_URL;
    const r = (await run(tsx, [cli, "monitor", "--store", "x"], { env }).catch((x) => x)) as { code: number; stderr: string; stdout: string };
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/ALERT .*monitor self-failure/);
    expect(r.stderr + r.stdout).not.toMatch(/s3cr3tpw/);
  });
});

/**
 * R26 (internal reviewer run 26) on real Postgres:
 *  - R26-P3-1: the deploy window holds an advisory lock (no overlap), refuses
 *    to open on a leftover membership, keeps the command's exit code on
 *    SIGINT, and a crash (SIGKILL) shows up in the monitor as "left open".
 *  - R26-P3-2: the monitor alerts on ANY member of the owner and on drift of
 *    the provider allowlist, the function definitions and the ACLs against
 *    deploy/integrity-manifest.json (which must match a fresh migrate + role SQL).
 *  - R26-P3-3: the role SQL revokes any membership in the owner.
 *  - R26-P3-4: the DB CHECK and mr_spend_release normalize hosts and refuse
 *    hex / decimal / octal IP forms and .local / .internal / .home.arpa.
 */
import { ANCHOR_PINS } from "./anchor.js";
import { afterAll, describe, expect, it } from "vitest";
import { execFile, spawn } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { promisify } from "node:util";
import pg from "pg";
import { MAINNET_PROFILE, TESTNET_PROFILE, toMicro } from "@mandaterail/core";
import { migratePostgres, PG_SCHEMA_VERSION, PgSpendStore } from "./pg.js";
import { driftStatus, EXPECTED_MR_TRIGGERS, integrityStatus, spendAudit } from "./spend-ops.js";
import { expectedProvidersHash, integrityReasons, loadIntegrityManifest, VERIFIER_SOFTKEY_PINS } from "./monitor.js";
import { closeShared, getPool, PG_URL, uid } from "./test-helpers.js";

afterAll(closeShared);
const run = promisify(execFile);
const ROOT = path.resolve(__dirname, "../../..");
const SQL = path.join(ROOT, "deploy/sql/t11-mr-reconcile-role.sql");
const WINDOW_SH = path.join(ROOT, "deploy/mr-admin-window.sh");
const WINDOW_SQL = path.join(ROOT, "deploy/sql/r25-admin-window.sql");
const MANIFEST = path.join(ROOT, "deploy/integrity-manifest.json");
const pwArgs = ["-v", "pw=t-rec-pw", "-v", "mon_pw=t-mon-pw", "-v", "rel_pw=t-rel-pw"];
const applyRoles = (url: string, extra: string[] = []) => run("psql", ["-X", "-q", "-v", "ON_ERROR_STOP=1", ...pwArgs, ...extra, "-d", url, "-f", SQL]);
const TN = TESTNET_PROFILE.caip2.slice(9);
const okVerify = async (p: { caip2: string }) => ({ genesisHash: p.caip2.slice(9) });
const dbUrl = (db: string) => PG_URL!.replace(/\/[^/]*$/, `/${db}`);
const PROVIDERS_HASH = expectedProvidersHash([{ network: "mainnet", allow: MAINNET_PROFILE.providerAllowlist }, { network: "testnet", allow: TESTNET_PROFILE.providerAllowlist }]);
const W = { network: "testnet", genesisHash: TN };
/** R27-P3-2: the throwaway cluster's superuser stands in for postgres. */
const HOLDER = { holderUser: PG_URL ? decodeURIComponent(new URL(PG_URL).username) : "postgres" };
function poolAs(role: string, pw: string, base: string): pg.Pool {
  const u = new URL(base);
  u.username = role;
  u.password = pw;
  const p = new pg.Pool({ connectionString: u.toString(), max: 2 });
  p.on("error", () => undefined);
  return p;
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** A database owned by a NOLOGIN-able plain mr_owner, migrated + role SQL (the host's shape). */
async function hostShapedDb(tag: string) {
  const admin = await getPool();
  const db = `mr_r26_${uid(tag).replace(/-/g, "_")}`;
  await admin.query("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mr_owner') THEN CREATE ROLE mr_owner; END IF; END $$");
  await admin.query("ALTER ROLE mr_owner LOGIN PASSWORD 't-own-pw' NOSUPERUSER");
  await admin.query(`CREATE DATABASE ${db} OWNER mr_owner`);
  const url = dbUrl(db);
  const own = poolAs("mr_owner", "t-own-pw", url);
  await migratePostgres(own, { network: "testnet", verifyNetwork: okVerify });
  await own.end();
  await applyRoles(url, ["-v", "admin_pw=t-adm-pw"]);
  const sup = new pg.Pool({ connectionString: url, max: 2 });
  sup.on("error", () => undefined);
  const members = async () => (await sup.query("SELECT coalesce(array_agg(m.rolname::text ORDER BY m.rolname), '{}') AS m FROM pg_auth_members am JOIN pg_roles m ON m.oid = am.member WHERE am.roleid = 'mr_owner'::regrole")).rows[0].m as string[];
  const cleanup = async () => {
    await sup.end();
    await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`);
    await admin.query("DROP OWNED BY mr_admin CASCADE").catch(() => undefined);
    await admin.query("DROP ROLE IF EXISTS mr_admin");
    await admin.query("DROP ROLE IF EXISTS mr_r26_intruder");
    await admin.query("DROP ROLE IF EXISTS mr_owner");
  };
  return { url, sup, members, cleanup, env: { ...process.env, MR_PSQL: `psql -d ${url}` } };
}

describe.skipIf(!PG_URL)("R26 hardening [postgres]", () => {
  it("R26-P3-2 / R27-P3-3: deploy/integrity-manifest.json matches a host-shaped migrate + role SQL", async () => {
    const h = await hostShapedDb("man");
    const sup = h.sup;
    try {
      const d = await driftStatus(sup);
      if (process.env.MR_UPDATE_INTEGRITY_MANIFEST === "1") {
        writeFileSync(MANIFEST, `${JSON.stringify({
          schemaVersion: PG_SCHEMA_VERSION, generatedBy: "packages/storage/src/r26-hardening.test.ts (MR_UPDATE_INTEGRITY_MANIFEST=1); then update INTEGRITY_MANIFEST_SHA256 in monitor.ts",
          functions: d.functions, aclHash: d.aclHash, aclFp: d.aclFp, constraintsHash: d.constraintsHash, ownersHash: d.ownersHash, triggersHash: d.triggersHash, rolesHash: d.rolesHash, releaseCaps: d.releaseCaps, anchor: ANCHOR_PINS, verifierSoftkey: VERIFIER_SOFTKEY_PINS,
        }, null, 2)}\n`);
      }
      const m = loadIntegrityManifest({ MONITOR_INTEGRITY_MANIFEST: MANIFEST });
      expect(m.schemaVersion).toBe(PG_SCHEMA_VERSION);
      expect(d.functions).toEqual(m.functions);
      expect(d.aclHash, d.aclText).toBe(m.aclHash);
      expect(d.aclFp).toBe(m.aclFp); // R70-P3-2
      expect(d.constraintsHash, d.constraintsText).toBe(m.constraintsHash);
      expect(d.ownersHash, d.ownersText).toBe(m.ownersHash);
      expect(d.triggersHash, d.triggersText).toBe(m.triggersHash);
      expect(d.rolesHash, d.rolesText).toBe(m.rolesHash);
      expect(d.releaseCaps).toEqual(m.releaseCaps);
      expect(m.anchor).toEqual(ANCHOR_PINS); // R66-P3-3
      expect(m.verifierSoftkey).toEqual(VERIFIER_SOFTKEY_PINS); // rev 24 §24.8
      expect(d.providersHash).toBe(PROVIDERS_HASH);
      // a monitor run against it: clean
      const i = await integrityStatus(sup, HOLDER);
      expect(integrityReasons(i, W, EXPECTED_MR_TRIGGERS, { ...m, providersHash: PROVIDERS_HASH })).toEqual([]);
      // drift: a function body, an allowlist row, a grant
      await sup.query("CREATE OR REPLACE FUNCTION mr_provider_host_refused(h text) RETURNS boolean LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $$ SELECT false $$");
      await sup.query("INSERT INTO mr_network_provider (network, host, operator_id) VALUES ('testnet', 'evil-node.example.com', 'evil')");
      await sup.query("GRANT SELECT ON mr_spend_audit TO PUBLIC");
      const r = integrityReasons(await integrityStatus(sup, HOLDER), W, EXPECTED_MR_TRIGGERS, { ...m, providersHash: PROVIDERS_HASH });
      expect(r).toEqual(expect.arrayContaining([
        expect.stringMatching(/provider allowlist drift .*12 rows/), // 11 profile rows (v13 getblock + v14 blockdaemon + v15 drpc) + the injected one
        expect.stringMatching(/function mr_provider_host_refused\(text\) definition drift/),
        expect.stringMatching(/ACL drift/),
      ]));
      // an extra function is drift too
      await sup.query("CREATE FUNCTION mr_backdoor() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$");
      expect(integrityReasons(await integrityStatus(sup, HOLDER), W, EXPECTED_MR_TRIGGERS, { ...m, providersHash: PROVIDERS_HASH })).toContain("integrity: unexpected function mr_backdoor()");
    } finally {
      await h.cleanup();
    }
  });

  it("R26-P3-1: window lock (no overlap), refuses on a leftover membership, keeps the rc on SIGINT, crash = left open", async () => {
    const h = await hostShapedDb("w");
    try {
      expect(await h.members()).toEqual([]);
      // 1. overlap: while window A runs, window B refuses and leaves A's membership alone
      const a = spawn("bash", [WINDOW_SH, "--", "sleep", "4"], { env: h.env, stdio: ["ignore", "ignore", "pipe"] });
      let aErr = "";
      a.stderr.on("data", (c) => (aErr += c));
      const aDone = new Promise<number>((r) => a.on("exit", (c) => r(c ?? -1)));
      for (let k = 0; k < 50 && !aErr.includes("open (mr_admin"); k++) await sleep(100);
      expect(aErr).toMatch(/open \(mr_admin/);
      expect((await integrityStatus(h.sup, HOLDER)).windowLockHeld).toBe(true);
      const b = (await run("bash", [WINDOW_SH, "--", "true"], { env: h.env }).catch((e) => e)) as { code: number; stderr: string };
      expect(b.code).toBe(1);
      expect(b.stderr).toMatch(/another deploy window holds the advisory lock/);
      expect(await h.members()).toEqual(["mr_admin"]); // B did not close A's window
      expect(await aDone).toBe(0);
      expect(aErr).toMatch(/closed/);
      expect(await h.members()).toEqual([]);

      // 2. SIGINT: the command's own exit code is kept (it traps INT and exits 5)
      const c = spawn("bash", [WINDOW_SH, "--", "bash", "-c", "trap 'exit 5' INT; sleep 6 & wait"], { env: h.env, stdio: ["ignore", "ignore", "pipe"], detached: true });
      let cErr = "";
      c.stderr.on("data", (x) => (cErr += x));
      const cDone = new Promise<number>((r) => c.on("exit", (code) => r(code ?? -1)));
      for (let k = 0; k < 50 && !cErr.includes("open (mr_admin"); k++) await sleep(100);
      await sleep(300);
      process.kill(-c.pid!, "SIGINT");
      expect(await cDone).toBe(5);
      expect(cErr).toMatch(/got SIGINT; keeping the command's exit code 5/);
      expect(await h.members()).toEqual([]);

      // 3. crash: SIGKILL the window script -> lock released, membership left -> monitor "left open"
      const d = spawn("bash", [WINDOW_SH, "--", "sleep", "30"], { env: h.env, stdio: ["ignore", "ignore", "pipe"], detached: true });
      let dErr = "";
      d.stderr.on("data", (x) => (dErr += x));
      for (let k = 0; k < 50 && !dErr.includes("open (mr_admin"); k++) await sleep(100);
      process.kill(d.pid!, "SIGKILL");
      let i = await integrityStatus(h.sup, HOLDER);
      for (let k = 0; k < 40 && i.windowLockHeld; k++) { await sleep(250); i = await integrityStatus(h.sup, HOLDER); }
      try { process.kill(-d.pid!, "SIGKILL"); } catch { /* group gone */ }
      expect(i.windowLockHeld).toBe(false);
      expect(i.ownerMembers).toEqual(["mr_admin"]);
      expect(integrityReasons(i, W, EXPECTED_MR_TRIGGERS)).toContain("integrity: deploy window left open (owner membership exists but no mr-admin-window lock holder; crashed?)");
      // a new window refuses to open on that leftover
      const e = (await run("bash", [WINDOW_SH, "--", "true"], { env: h.env }).catch((x) => x)) as { code: number; stderr: string };
      expect(e.code).toBe(1);
      expect(e.stderr).toMatch(/refusing to open: mr_admin already member/);
      expect(await h.members()).toEqual(["mr_admin"]); // and did not "close" it either
      // opening by hand without the lock holder is refused by the SQL itself
      await h.sup.query("REVOKE mr_owner FROM mr_admin");
      await expect(run("psql", ["-X", "-q", "-v", "ON_ERROR_STOP=1", "-v", "window=open", "-d", h.url, "-f", WINDOW_SQL])).rejects.toMatchObject({ stderr: expect.stringMatching(/no deploy-window lock holder/) });
    } finally {
      await h.cleanup();
    }
  }, 90_000);

  it("R26-P3-2 / P3-3: any owner member alerts; the role SQL revokes every membership in the owner", async () => {
    const h = await hostShapedDb("m");
    try {
      await h.sup.query("CREATE ROLE mr_r26_intruder NOLOGIN");
      await h.sup.query("GRANT mr_owner TO mr_r26_intruder");
      await h.sup.query("GRANT mr_owner TO mr_admin WITH INHERIT FALSE, SET TRUE"); // a leftover v8 standing grant
      const mon = poolAs("mr_monitor", "t-mon-pw", h.url);
      try {
        const i = await integrityStatus(mon, HOLDER);
        expect(i.ownerMembers).toEqual(["mr_admin", "mr_r26_intruder"]);
        const r = integrityReasons(i, W, EXPECTED_MR_TRIGGERS);
        expect(r).toContain("integrity: mr_r26_intruder is a member of the table owner (revoke: re-run the role SQL)");
        expect(r).toEqual(expect.arrayContaining([expect.stringMatching(/mr_admin is a member/), expect.stringMatching(/left open/)]));
        const out = await applyRoles(h.url);
        expect(out.stderr).toMatch(/R26-P3-3: revoking leftover membership of mr_admin/);
        expect(out.stderr).toMatch(/R26-P3-3: revoking leftover membership of mr_r26_intruder/);
        expect(await h.members()).toEqual([]);
        const after = await integrityStatus(mon, HOLDER);
        expect(after).toMatchObject({ adminOwnerMember: false, ownerMembers: [] });
        expect(integrityReasons(after, W, EXPECTED_MR_TRIGGERS)).toEqual([]);
      } finally {
        await mon.end();
      }
    } finally {
      await h.cleanup();
    }
  });

  it("R26-P3-4: the DB CHECK and mr_spend_release refuse IP forms / private suffixes and normalize hosts", async () => {
    const pool = await getPool();
    await applyRoles(PG_URL!);
    for (const host of ["0x7f000001", "2130706433", "0177.0.0.1", "0x7f.0.0.1", "127.1", "foo.123", "printer.local", "db.internal", "nas.home.arpa", "Upper.example", "dot.example.", "a..b.example"]) {
      await expect(pool.query("INSERT INTO mr_network_provider (network, host, operator_id) VALUES ('testnet', $1, 'x')", [host]), host).rejects.toThrow(/check constraint|violates/);
    }
    expect((await pool.query("SELECT mr_provider_host_refused('testnet-idx.algonode.cloud') AS r")).rows[0].r).toBe(false);
    const store = uid("r26");
    const s = new PgSpendStore(pool, { store });
    const caps = { perPaymentMicro: toMicro("1"), perDayMicro: toMicro("5") };
    await s.reserve({ id: "g", payer: "P", amountMicro: 1n, caps, nowMs: Date.now() });
    await s.attachTxId("g", "TXG", Date.now(), 900);
    await s.finalize("g", "ambiguous", Date.now());
    const rel = poolAs("mr_release", "t-rel-pw", PG_URL!);
    const REL = "SELECT * FROM mr_spend_release($1,'g','manual-release','david','operator check','TXG',900,10,$2,'indexer',$4,1500,404,$3,'indexer',$4,1500,404)";
    try {
      for (const bad of ["0x7f000001", "2130706433", "0177.0.0.1", "node.local", "x.internal", "y.home.arpa"]) {
        await expect(rel.query(REL, [store, bad, "idx-b.example", TN]), bad).rejects.toThrow(/refused|must be a host/);
      }
      // upper case + trailing dot + port normalize onto the allowlisted hosts
      expect((await rel.query(REL, [store, "IDX-A.Example.", "idx-b.example.:443", TN])).rows[0]).toEqual({ ok: true, from_status: "ambiguous" });
      expect((await spendAudit(pool, store, "g"))[0]).toMatchObject({ proof_operator: "test-op-a", proof2_operator: "test-op-b" });
    } finally {
      await rel.end();
    }
  });
});

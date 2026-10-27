/**
 * R25 (internal reviewer run 25) on real Postgres:
 *  - R25-P2-1 (partial): the DB enforces the provider allowlist
 *    (mr_network_provider: host -> operator id per network); the two
 *    observations need two DIFFERENT operator ids; loopback / localhost /
 *    .invalid / IP literals are refused; operator ids land in the audit row.
 *  - R25-P3-1: deploy/mr-admin-window.sh grants mr_admin's owner membership
 *    only for the wrapped command (revoked on error too); the monitor checks
 *    tgenabled + the network marker + the membership on every run.
 *  - R25-P3-2: imports SET LOCAL ROLE inside the transaction, awaited, fatal.
 */
import { afterAll, describe, expect, it } from "vitest";
import { execFile } from "node:child_process";
import { writeFile, mkdtemp } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import pg from "pg";
import { TESTNET_PROFILE, MAINNET_PROFILE, toMicro } from "@mandaterail/core";
import { migratePostgres, PgSpendStore } from "./pg.js";
import { EXPECTED_MR_TRIGGERS, integrityStatus, spendAudit } from "./spend-ops.js";
import { integrityReasons, runMonitor } from "./monitor.js";
import { importConsoleJson, importInTransaction, ImportRoleError } from "./import-json.js";
import { closeShared, getPool, PG_URL, uid } from "./test-helpers.js";

afterAll(closeShared);
const run = promisify(execFile);
const ROOT = path.resolve(__dirname, "../../..");
const SQL = path.join(ROOT, "deploy/sql/t11-mr-reconcile-role.sql");
const WINDOW_SH = path.join(ROOT, "deploy/mr-admin-window.sh");
const pwArgs = ["-v", "pw=t-rec-pw", "-v", "mon_pw=t-mon-pw", "-v", "rel_pw=t-rel-pw"];
const applyRoles = (url = PG_URL!, extra: string[] = []) => run("psql", ["-X", "-q", "-v", "ON_ERROR_STOP=1", ...pwArgs, ...extra, "-d", url, "-f", SQL]);
const TN = TESTNET_PROFILE.caip2.slice(9);
const caps = { perPaymentMicro: toMicro("1"), perDayMicro: toMicro("5") };
const okVerify = async (p: { caip2: string }) => ({ genesisHash: p.caip2.slice(9) });
const dbUrl = (db: string) => PG_URL!.replace(/\/[^/]*$/, `/${db}`);
function poolAs(role: string, pw: string, base = PG_URL!): pg.Pool {
  const u = new URL(base);
  u.username = role;
  u.password = pw;
  const p = new pg.Pool({ connectionString: u.toString(), max: 2 });
  p.on("error", () => undefined);
  return p;
}
const REL = "SELECT * FROM mr_spend_release($1,$2,'manual-release','david','operator check',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)";
type Obs = [string, string, string, number, number];
const good = (p: string, kind = "indexer", round = 1500): Obs => [p, kind, TN, round, 404];

describe.skipIf(!PG_URL)("R25 hardening [postgres]", () => {
  it("R25-P2-1: the DB allowlist needs two different operators; the run-25 bypass pairs are refused", async () => {
    await applyRoles();
    const pool = await getPool();
    const store = uid("r25");
    const s = new PgSpendStore(pool, { store });
    await s.reserve({ id: "g", payer: "P", amountMicro: 1n, caps, nowMs: Date.now() });
    await s.attachTxId("g", "TXG", Date.now(), 900);
    await s.finalize("g", "ambiguous", Date.now());
    // the migrations seeded the profile allowlists (nodely on both networks; v13 adds getblock, v14 blockdaemon, on MainNet)
    const seeded = await pool.query("SELECT network, host, operator_id FROM mr_network_provider WHERE operator_id IN ('nodely', 'getblock', 'blockdaemon', 'drpc') ORDER BY 1, 2");
    expect(seeded.rows).toEqual(
      [...TESTNET_PROFILE.providerAllowlist.map((e) => ({ network: "testnet", host: e.host, operator_id: e.operator })),
       ...MAINNET_PROFILE.providerAllowlist.map((e) => ({ network: "mainnet", host: e.host, operator_id: e.operator }))]
        .sort((a, b) => (a.network + a.host).localeCompare(b.network + b.host)),
    );
    expect(seeded.rows.filter((r) => r.operator_id === "getblock")).toEqual([{ network: "mainnet", host: "shared.eu-central-1.getblock.io", operator_id: "getblock" }]);
    const bd = await pool.query("SELECT network, host, operator_id FROM mr_network_provider WHERE operator_id = 'blockdaemon'");
    expect(bd.rows).toEqual([{ network: "mainnet", host: "svc.blockdaemon.com", operator_id: "blockdaemon" }]);
    const rel = poolAs("mr_release", "t-rel-pw");
    try {
      const q = (o1: Obs, o2: Obs) => rel.query(REL, [store, "g", "TXG", 900, 10, ...o1, ...o2]);
      await expect(q(good("127.0.0.1"), good("localhost"))).rejects.toThrow(/observation 1 provider 127\.0\.0\.1 is loopback/);
      await expect(q(good("idx-a.example"), good("localhost"))).rejects.toThrow(/observation 2 provider localhost is loopback/);
      await expect(q(good("idx-a.example"), good("idx-a.example:443"))).rejects.toThrow(/different operators/);
      await expect(q(good("x.invalid"), good("y.invalid"))).rejects.toThrow(/\.invalid/);
      await expect(q(good("idx-a.example"), good("unlisted.example.com"))).rejects.toThrow(/not on the testnet provider allowlist/);
      await expect(q(good("idx-a.example"), good("algod-a.example", "algod"))).rejects.toThrow(/both are test-op-a/);
      // the only real TestNet operator: algonode + nodely hosts are one operator
      await expect(q(good("testnet-idx.algonode.cloud"), good("testnet-api.4160.nodely.dev", "algod"))).rejects.toThrow(/both are nodely/);
      // a MainNet host is not on the TestNet list
      await expect(q(good("idx-a.example"), good("mainnet-idx.algonode.cloud"))).rejects.toThrow(/not on the testnet provider allowlist/);
      expect((await s.get("g"))!.status).toBe("ambiguous");
      expect((await q(good("testnet-idx.algonode.cloud"), good("idx-b.example:8443"))).rows[0]).toEqual({ ok: true, from_status: "ambiguous" });
      expect((await spendAudit(pool, store, "g"))[0]).toMatchObject({ proof_provider: "testnet-idx.algonode.cloud", proof_operator: "nodely", proof2_provider: "idx-b.example:8443", proof2_operator: "test-op-b" });
      // nobody but the owner writes the allowlist; the table CHECK refuses loopback / .invalid / IPs
      await expect(rel.query("INSERT INTO mr_network_provider (network, host, operator_id) VALUES ('testnet', 'evil.example', 'x')")).rejects.toThrow(/permission denied/);
      for (const h of ["localhost", "127.0.0.1", "a.invalid", "b.localhost"]) {
        await expect(pool.query("INSERT INTO mr_network_provider (network, host, operator_id) VALUES ('testnet', $1, 'x')", [h])).rejects.toThrow(/check constraint/);
      }
    } finally {
      await rel.end();
    }
  });

  it("R25-P3-1: deploy window grants mr_admin's owner membership only for the command, and revokes it on error", async () => {
    const admin = await getPool();
    const db = `mr_r25_${uid("w").replace(/-/g, "_")}`;
    await admin.query("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mr_owner') THEN CREATE ROLE mr_owner; END IF; END $$");
    await admin.query("ALTER ROLE mr_owner LOGIN PASSWORD 't-own-pw' NOSUPERUSER");
    await admin.query(`CREATE DATABASE ${db} OWNER mr_owner`);
    const url = dbUrl(db);
    const own = poolAs("mr_owner", "t-own-pw", url);
    const env = { ...process.env, MR_PSQL: `psql -d ${url}` };
    const member = async () => (await admin.query("SELECT pg_has_role('mr_admin', 'mr_owner', 'MEMBER') AS m")).rows[0].m as boolean;
    try {
      await migratePostgres(own, { network: "testnet", verifyNetwork: okVerify });
      await own.end();
      await applyRoles(url, ["-v", "admin_pw=t-adm-pw"]);
      expect(await member()).toBe(false); // the role SQL never grants it
      // during the window: member (SET only); after: not
      const probe = `psql -X -tA -d ${url} -c "SELECT pg_has_role('mr_admin','mr_owner','MEMBER')"`;
      const ok = await run("bash", [WINDOW_SH, "--", "sh", "-c", probe], { env });
      expect(ok.stdout.trim()).toBe("t");
      expect(ok.stderr).toMatch(/closed/);
      expect(await member()).toBe(false);
      // a failing deploy step keeps its exit code and still revokes
      const bad = (await run("bash", [WINDOW_SH, "--", "sh", "-c", `${probe}; exit 7`], { env }).catch((e) => e)) as { code: number; stdout: string };
      expect(bad.code).toBe(7);
      expect(bad.stdout.trim()).toBe("t");
      expect(await member()).toBe(false);
      // a migrate inside the window works as mr_owner; outside, SET ROLE is refused
      const adm = poolAs("mr_admin", "t-adm-pw", url);
      try {
        await expect(migratePostgres(adm, { network: "testnet", setRole: "mr_owner", verifyNetwork: okVerify })).rejects.toThrow(/permission denied to set role/);
      } finally {
        await adm.end();
      }
      // a membership left behind outside a window (granted by hand here) is flagged by the monitor ...
      const sup = new pg.Pool({ connectionString: url, max: 1 });
      sup.on("error", () => undefined);
      try {
        await sup.query("GRANT mr_owner TO mr_admin WITH INHERIT FALSE, SET TRUE, ADMIN FALSE");
        const i = await integrityStatus(sup);
        expect(i.adminOwnerMember).toBe(true);
        expect(integrityReasons(i, { network: "testnet", genesisHash: TN }, EXPECTED_MR_TRIGGERS)).toEqual([
          expect.stringMatching(/mr_admin is a member of the table owner outside a deploy window/),
          expect.stringMatching(/deploy window left open/),
        ]);
      } finally {
        await sup.end();
      }
      // ... and R26-P3-3: the role SQL revokes it
      await applyRoles(url);
      expect(await member()).toBe(false);
      await run("psql", ["-X", "-q", "-v", "ON_ERROR_STOP=1", "-v", "window=close", "-d", url, "-f", path.join(ROOT, "deploy/sql/r25-admin-window.sql")]);
      expect(await member()).toBe(false);
    } finally {
      await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`);
      await admin.query("DROP OWNED BY mr_admin CASCADE").catch(() => undefined);
      await admin.query("DROP ROLE IF EXISTS mr_admin");
      await admin.query("DROP ROLE IF EXISTS mr_owner");
    }
  });

  it("R25-P3-1: the monitor checks tgenabled on all triggers and the marker on every run (as mr_monitor)", async () => {
    const admin = await getPool();
    const db = `mr_r25_${uid("m").replace(/-/g, "_")}`;
    await admin.query(`CREATE DATABASE ${db}`);
    const url = dbUrl(db);
    const sup = new pg.Pool({ connectionString: url, max: 2 });
    sup.on("error", () => undefined);
    const mon = poolAs("mr_monitor", "t-mon-pw", url);
    const fetchOk = (async () => new Response("{}", { status: 200 })) as unknown as typeof fetch;
    const env = { MONITOR_HEALTH_URLS: "https://h.example/health" };
    const once = (want = { network: "testnet", genesisHash: TN }) => {
      const err: string[] = [];
      return runMonitor({
        env, store: "demo-api", olderThanMin: 30, stale: async () => ({ pending: 0, ambiguous: 0, oldestAgeMs: null }),
        integrity: { read: () => integrityStatus(mon), want, expectedTriggers: EXPECTED_MR_TRIGGERS },
        fetchImpl: fetchOk, log: () => undefined, err: (l) => err.push(l),
      }).then((r) => ({ ...r, err }));
    };
    try {
      await migratePostgres(sup, { network: "testnet", verifyNetwork: okVerify });
      await applyRoles(url);
      const i = await integrityStatus(mon);
      for (const k of EXPECTED_MR_TRIGGERS) expect(i.triggers[k]).toBe("O");
      expect(i.marker).toEqual({ network: "testnet", genesisHash: TN });
      expect(await once()).toMatchObject({ ok: true, exitCode: 0 });
      // a disabled trigger alerts
      await sup.query("ALTER TABLE mr_spend_audit DISABLE TRIGGER mr_spend_audit_no_update");
      const r1 = await once();
      expect(r1).toMatchObject({ ok: false, exitCode: 2 });
      expect(r1.reasons).toContain("integrity: trigger mr_spend_audit.mr_spend_audit_no_update is not enabled (tgenabled D)");
      expect(r1.err[0]).toMatch(/^ALERT /);
      await sup.query("ALTER TABLE mr_spend_audit ENABLE TRIGGER mr_spend_audit_no_update");
      // a REPLICA-only trigger is not 'O' either
      await sup.query("ALTER TABLE mr_spend ENABLE REPLICA TRIGGER mr_spend_guard_row");
      expect((await once()).reasons).toContain("integrity: trigger mr_spend.mr_spend_guard_row is not enabled (tgenabled R)");
      await sup.query("ALTER TABLE mr_spend ENABLE TRIGGER mr_spend_guard_row");
      // a dropped trigger alerts as missing
      await sup.query("DROP TRIGGER mr_network_no_truncate ON mr_network");
      expect((await once()).reasons).toContain("integrity: trigger mr_network.mr_network_no_truncate is missing");
      // a marker for another network than NETWORK's profile alerts
      const r3 = await once({ network: "mainnet", genesisHash: MAINNET_PROFILE.caip2.slice(9) });
      expect(r3.reasons.join("\n")).toMatch(/network marker is testnet\/.* expected mainnet/);
      // the integrity query failing is a monitor self-failure alert
      const r4 = await runMonitor({ env, store: "s", olderThanMin: 30, stale: async () => ({ pending: 0, ambiguous: 0, oldestAgeMs: null }), integrity: { read: async () => { throw Object.assign(new Error("x"), { code: "ECONNREFUSED" }); }, want: { network: "testnet", genesisHash: TN }, expectedTriggers: EXPECTED_MR_TRIGGERS }, fetchImpl: fetchOk, log: () => undefined, err: () => undefined });
      expect(r4).toMatchObject({ ok: false, exitCode: 2, reasons: ["monitor self-failure: integrity query failed (ECONNREFUSED)"] });
    } finally {
      await mon.end();
      await sup.end();
      await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`);
    }
  });

  it("missing marker alerts", () => {
    expect(integrityReasons({ triggers: Object.fromEntries(EXPECTED_MR_TRIGGERS.map((k) => [k, "O"])), marker: null, adminOwnerMember: false }, { network: "testnet", genesisHash: TN }, EXPECTED_MR_TRIGGERS))
      .toEqual(["integrity: network marker (mr_network) is not set"]);
  });

  it("R25-P3-2: import SET LOCAL ROLE is awaited inside the transaction and fatal on failure", async () => {
    const pool = await getPool();
    const role = `mr_r25_imp_${uid("r").replace(/-/g, "_")}`;
    await pool.query(`CREATE ROLE ${role} NOLOGIN`);
    const dir = await mkdtemp(path.join(os.tmpdir(), "r25-imp-"));
    const file = path.join(dir, "m.json");
    await writeFile(file, "[]");
    try {
      await expect(importInTransaction(pool, "mr_nonexistent_role_x", async () => "ran")).rejects.toThrow(ImportRoleError);
      await expect(importInTransaction(pool, "bad; DROP", async () => "ran")).rejects.toThrow(/plain role name/);
      // inside: current_user is the role for every statement (one client, one transaction)
      const who = await importInTransaction(pool, role, async (q) => (await q.query("SELECT current_user::text AS u")).rows[0].u);
      expect(who).toBe(role);
      // the role lacks rights -> the import fails and nothing is committed
      await expect(importInTransaction(pool, role, (q) => importConsoleJson(q, file).then(async (r) => {
        await q.query("INSERT INTO mr_mandates (store, id, mandate, server_verified) VALUES ('x', 'y', '{}', false)");
        return r;
      }))).rejects.toThrow(/permission denied/);
      // after the transaction the session is back to the login role
      expect((await pool.query("SELECT current_user::text AS u")).rows[0].u).not.toBe(role);
    } finally {
      await pool.query(`DROP ROLE IF EXISTS ${role}`);
    }
  });
});

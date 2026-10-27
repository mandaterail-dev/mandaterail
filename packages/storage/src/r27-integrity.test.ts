/**
 * internal reviewer run 27:
 *  - R27-P3-1: the manifest sha256 (md5 until R29) is pinned in code; MONITOR_INTEGRITY_MANIFEST is
 *    refused on mainnet / NODE_ENV=production; missing / tampered = page + exit 2.
 *  - R27-P3-2: only postgres/mr-admin-window may hold lock (26026,1), for <= 30 min.
 *  - R27-P3-3: constraint definitions, owners, trigger definitions and role
 *    flags are in the manifest; dropping the allowlist CHECK is drift.
 */
import { afterAll, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { copyFileSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import pg from "pg";
import { MAINNET_PROFILE, TESTNET_PROFILE } from "@mandaterail/core";
import { migratePostgres } from "./pg.js";
import { EXPECTED_MR_TRIGGERS, integrityStatus, WINDOW_HOLDER } from "./spend-ops.js";
import { DEFAULT_MANIFEST_PATH, expectedProvidersHash, INTEGRITY_MANIFEST_SHA256, integrityReasons, loadIntegrityManifest, MonitorManifestError, monitorSelfFailure, type MonitorIntegrity } from "./monitor.js";
import { closeShared, getPool, PG_URL, uid } from "./test-helpers.js";

afterAll(closeShared);
const run = promisify(execFile);
const ROOT = path.resolve(__dirname, "../../..");
const SQL = path.join(ROOT, "deploy/sql/t11-mr-reconcile-role.sql");
const TN = TESTNET_PROFILE.caip2.slice(9);
const W = { network: "testnet", genesisHash: TN };
const PROVIDERS_HASH = expectedProvidersHash([{ network: "mainnet", allow: MAINNET_PROFILE.providerAllowlist }, { network: "testnet", allow: TESTNET_PROFILE.providerAllowlist }]);
const HOLDER = { holderUser: PG_URL ? decodeURIComponent(new URL(PG_URL).username) : "postgres" };

describe("R27-P3-1 pinned manifest", () => {
  it("the pinned sha256 equals deploy/integrity-manifest.json (update both together)", () => {
    expect(createHash("sha256").update(readFileSync(DEFAULT_MANIFEST_PATH)).digest("hex")).toBe(INTEGRITY_MANIFEST_SHA256);
    expect(loadIntegrityManifest({ NETWORK: "mainnet", NODE_ENV: "production" }).rolesHash).toMatch(/^[0-9a-f]{32}$/);
  });
  it("a tampered manifest (even through the override) is refused", () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "mr-man-"));
    const f = path.join(dir, "m.json");
    const j = JSON.parse(readFileSync(DEFAULT_MANIFEST_PATH, "utf8"));
    j.functions["mr_spend_guard()"] = "00000000000000000000000000000000";
    writeFileSync(f, JSON.stringify(j, null, 2) + "\n");
    expect(() => loadIntegrityManifest({ NETWORK: "testnet", MONITOR_INTEGRITY_MANIFEST: f })).toThrow(/does not match the pinned/);
    copyFileSync(DEFAULT_MANIFEST_PATH, f); // an exact copy passes (testnet, not production)
    expect(loadIntegrityManifest({ NETWORK: "testnet", MONITOR_INTEGRITY_MANIFEST: f }).aclHash).toMatch(/^[0-9a-f]{32}$/);
  });
  it("the override is refused on mainnet and in production", () => {
    for (const env of [{ NETWORK: "mainnet" }, { NETWORK: "MainNet" }, { NETWORK: "testnet", NODE_ENV: "production" }]) {
      expect(() => loadIntegrityManifest({ ...env, MONITOR_INTEGRITY_MANIFEST: DEFAULT_MANIFEST_PATH }), JSON.stringify(env)).toThrow(/MONITOR_INTEGRITY_MANIFEST is refused/);
    }
  });
  it("a missing manifest is a MonitorManifestError that pages and exits 2 (not a config error)", async () => {
    let e: unknown;
    try {
      loadIntegrityManifest({ NETWORK: "testnet", MONITOR_INTEGRITY_MANIFEST: "/nonexistent/m.json" });
    } catch (x) {
      e = x;
    }
    expect(e).toBeInstanceOf(MonitorManifestError);
    expect((e as MonitorManifestError).code).toBe("MANIFEST_MISSING");
    const posts: string[] = [];
    const f = (async (_u: string, init?: RequestInit) => { posts.push(String(init?.body)); return new Response("ok"); }) as unknown as typeof fetch;
    const lines: string[] = [];
    const r = await monitorSelfFailure({ env: { MONITOR_PAGER_WEBHOOK_URL: "https://pager.example/hook", MONITOR_PAGER_FORMAT: "slack" }, store: "s", error: e, fetchImpl: f, err: (l) => lines.push(l) });
    expect(r).toMatchObject({ exitCode: 2, pager: "sent" });
    expect(posts[0]).toMatch(/integrity manifest: MANIFEST_MISSING/);
  });
  it("the monitor CLI exits 2 when the manifest can't be used (override refused on mainnet)", async () => {
    const cli = path.join(ROOT, "packages/storage/src/spend-cli.ts");
    const r = (await run(path.join(ROOT, "node_modules/.bin/tsx"), [cli, "monitor"], {
      env: { PATH: process.env.PATH, NETWORK: "mainnet", ALLOW_MAINNET: "1", DATABASE_URL: "postgres://x@127.0.0.1:1/x", MONITOR_HEALTH_URLS: "https://h.example/health", MONITOR_INTEGRITY_MANIFEST: DEFAULT_MANIFEST_PATH, STATE_ENV_FILE: "/dev/null" },
    }).catch((x) => x)) as { code: number; stderr: string };
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/MANIFEST_OVERRIDE_REFUSED/);
  }, 60_000);
});

describe("R27-P3-2 window lock holder", () => {
  const base: MonitorIntegrity = { triggers: Object.fromEntries(EXPECTED_MR_TRIGGERS.map((t) => [t, "O"])), marker: { network: "testnet", genesisHash: TN }, adminOwnerMember: false, ownerMembers: [] };
  it("a foreign holder alerts; a valid holder past 30 min alerts; a fresh valid holder is fine", () => {
    expect(integrityReasons({ ...base, windowLockHolders: [{ pid: 7, user: "mr_release", app: "psql", ageS: 5, valid: false }] }, W, EXPECTED_MR_TRIGGERS))
      .toEqual([expect.stringMatching(/lock \(26026,1\) held by an unexpected session \(pid 7, user mr_release/)]);
    expect(integrityReasons({ ...base, windowLockHolders: [{ pid: 8, user: "postgres", app: "mr-admin-window", ageS: 31 * 60, valid: true }] }, W, EXPECTED_MR_TRIGGERS))
      .toEqual([expect.stringMatching(/open too long \(31 min > 30 min/)]);
    expect(integrityReasons({ ...base, windowLockHolders: [{ pid: 9, user: "postgres", app: "mr-admin-window", ageS: null, valid: true }] }, W, EXPECTED_MR_TRIGGERS))
      .toEqual([expect.stringMatching(/session age unreadable/)]);
    expect(integrityReasons({ ...base, windowLockHolders: [{ pid: 9, user: "postgres", app: "mr-admin-window", ageS: 60, valid: true }] }, W, EXPECTED_MR_TRIGGERS)).toEqual([]);
    expect(WINDOW_HOLDER).toMatchObject({ user: "postgres", app: "mr-admin-window" });
  });
});

function poolAs(role: string, pw: string, base: string): pg.Pool {
  const u = new URL(base);
  u.username = role;
  u.password = pw;
  const p = new pg.Pool({ connectionString: u.toString(), max: 2 });
  p.on("error", () => undefined);
  return p;
}

describe.skipIf(!PG_URL)("R27 [postgres]", () => {
  async function hostDb(tag: string) {
    const admin = await getPool();
    const db = `mr_r27_${uid(tag).replace(/-/g, "_")}`;
    await admin.query("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mr_owner') THEN CREATE ROLE mr_owner; END IF; END $$");
    await admin.query("ALTER ROLE mr_owner LOGIN PASSWORD 't-own-pw' NOSUPERUSER");
    await admin.query(`CREATE DATABASE ${db} OWNER mr_owner`);
    const url = PG_URL!.replace(/\/[^/]*$/, `/${db}`);
    const own = poolAs("mr_owner", "t-own-pw", url);
    await migratePostgres(own, { network: "testnet", verifyNetwork: async (p: { caip2: string }) => ({ genesisHash: p.caip2.slice(9) }) });
    await own.end();
    await run("psql", ["-X", "-q", "-v", "ON_ERROR_STOP=1", "-v", "pw=t-rec-pw", "-v", "mon_pw=t-mon-pw", "-v", "rel_pw=t-rel-pw", "-v", "admin_pw=t-adm-pw", "-d", url, "-f", SQL]);
    const sup = new pg.Pool({ connectionString: url, max: 3 });
    sup.on("error", () => undefined);
    return {
      url, sup,
      cleanup: async () => {
        await sup.end();
        await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`);
        await admin.query("DROP OWNED BY mr_admin CASCADE").catch(() => undefined);
        await admin.query("DROP ROLE IF EXISTS mr_admin");
        await admin.query("DROP ROLE IF EXISTS mr_owner");
      },
    };
  }

  it("R27-P3-3: dropping the allowlist CHECK, re-owning a table, editing a trigger, or changing a role flag is drift", async () => {
    const h = await hostDb("drift");
    const m = { ...loadIntegrityManifest({}), providersHash: PROVIDERS_HASH };
    const mon = poolAs("mr_monitor", "t-mon-pw", h.url);
    try {
      expect(integrityReasons(await integrityStatus(mon, HOLDER), W, EXPECTED_MR_TRIGGERS, m)).toEqual([]);
      const con = (await h.sup.query("SELECT conname FROM pg_constraint WHERE conrelid = 'mr_network_provider'::regclass AND contype = 'c' LIMIT 1")).rows[0].conname as string;
      await h.sup.query(`ALTER TABLE mr_network_provider DROP CONSTRAINT ${con}`);
      expect(integrityReasons(await integrityStatus(mon, HOLDER), W, EXPECTED_MR_TRIGGERS, m)).toEqual([expect.stringMatching(/^integrity: constraint drift/)]);
      await h.sup.query("CREATE ROLE mr_r27_other NOLOGIN");
      await h.sup.query("ALTER TABLE mr_schema OWNER TO mr_r27_other");
      expect(integrityReasons(await integrityStatus(mon, HOLDER), W, EXPECTED_MR_TRIGGERS, m)).toEqual(expect.arrayContaining([expect.stringMatching(/^integrity: owner drift/)]));
      await h.sup.query("ALTER TABLE mr_schema OWNER TO mr_owner");
      await h.sup.query("ALTER ROLE mr_monitor CONNECTION LIMIT 50");
      expect(integrityReasons(await integrityStatus(mon, HOLDER), W, EXPECTED_MR_TRIGGERS, m)).toEqual(expect.arrayContaining([expect.stringMatching(/^integrity: role flag \/ membership drift/)]));
      await h.sup.query("DROP TRIGGER mr_network_no_truncate ON mr_network");
      await h.sup.query("CREATE TRIGGER mr_network_no_truncate BEFORE TRUNCATE ON mr_network FOR EACH STATEMENT WHEN (false) EXECUTE FUNCTION mr_network_write_once()").catch(async () => {
        await h.sup.query("CREATE TRIGGER mr_network_no_truncate AFTER TRUNCATE ON mr_network FOR EACH STATEMENT EXECUTE FUNCTION mr_network_write_once()");
      });
      expect(integrityReasons(await integrityStatus(mon, HOLDER), W, EXPECTED_MR_TRIGGERS, m)).toEqual(expect.arrayContaining([expect.stringMatching(/^integrity: trigger definition drift/)]));
    } finally {
      await mon.end();
      await h.cleanup();
      await (await getPool()).query("DROP ROLE IF EXISTS mr_r27_other");
    }
  });

  it("R27-P3-2: a non-window session holding (26026,1) alerts; mr_monitor sees the holder's user, app and age", async () => {
    const h = await hostDb("lock");
    const rel = poolAs("mr_release", "t-rel-pw", h.url);
    const mon = poolAs("mr_monitor", "t-mon-pw", h.url);
    const c = await rel.connect();
    try {
      await c.query("SELECT pg_advisory_lock(26026, 1)");
      const i = await integrityStatus(mon, HOLDER);
      expect(i.windowLockHeld).toBe(false);
      expect(i.windowLockHolders).toEqual([expect.objectContaining({ user: "mr_release", valid: false })]);
      expect(i.windowLockHolders![0]!.ageS).not.toBeNull();
      expect(integrityReasons(i, W, EXPECTED_MR_TRIGGERS)).toEqual([expect.stringMatching(/held by an unexpected session .*user mr_release/)]);
      await c.query("SELECT pg_advisory_unlock(26026, 1)");
      // a superuser session with the right name is a valid holder; the wrong name is not
      const s = await h.sup.connect();
      try {
        await s.query("SET application_name = 'mr-admin-window'");
        await s.query("SELECT pg_advisory_lock(26026, 1)");
        let j = await integrityStatus(mon, HOLDER);
        expect(j.windowLockHeld).toBe(true);
        expect(integrityReasons(j, W, EXPECTED_MR_TRIGGERS)).toEqual([]);
        await s.query("SET application_name = 'psql'");
        j = await integrityStatus(mon, HOLDER);
        expect(j.windowLockHeld).toBe(false);
        expect(integrityReasons(j, W, EXPECTED_MR_TRIGGERS)).toEqual([expect.stringMatching(/unexpected session/)]);
        // and the window SQL refuses to open next to a foreign holder
        await s.query("SET application_name = 'not-the-window'");
        await expect(run("psql", ["-X", "-q", "-v", "ON_ERROR_STOP=1", "-v", "window=open", "-d", h.url, "-f", path.join(ROOT, "deploy/sql/r25-admin-window.sql")]))
          .rejects.toMatchObject({ stderr: expect.stringMatching(/held by a session that is not/) });
        await s.query("SELECT pg_advisory_unlock(26026, 1)");
      } finally {
        s.release();
      }
    } finally {
      c.release();
      await rel.end();
      await mon.end();
      await h.cleanup();
    }
  }, 60_000);
});

/**
 * internal reviewer run 28:
 *  - R28-P3-2: mr_monitor holds no pg_read_all_stats; it reads the window-lock
 *    holders through the superuser-owned SECURITY DEFINER mr_window_lock_holders()
 *    (EXECUTE for mr_monitor only) and cannot read other sessions' query text.
 *  - R28-P3-1: /etc/mandaterail/release-pin (root-owned) pins the commit, the
 *    release tree hash and the manifest md5; the monitor alerts on any mismatch.
 *  - R28-P3-3: role settings (global + per-database) must be empty and connection
 *    limits match the role SQL for every managed role, app roles and owner included.
 */
import { afterAll, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import pg from "pg";
import { MAINNET_PROFILE, TESTNET_PROFILE } from "@mandaterail/core";
import { migratePostgres } from "./pg.js";
import { EXPECTED_MR_TRIGGERS, integrityStatus } from "./spend-ops.js";
import { DEFAULT_MANIFEST_PATH, expectedProvidersHash, INTEGRITY_MANIFEST_SHA256, integrityReasons, loadIntegrityManifest, runMonitor } from "./monitor.js";
import { formatReleasePin, parseReleasePin, releaseDepsHash, releasePinReasons, releaseTreeHash, systemdState } from "./release-pin.js";
import { closeShared, getPool, PG_URL, uid } from "./test-helpers.js";

afterAll(closeShared);
const run = promisify(execFile);
const ROOT = path.resolve(__dirname, "../../..");
const SQL = path.join(ROOT, "deploy/sql/t11-mr-reconcile-role.sql");
const TN = TESTNET_PROFILE.caip2.slice(9);
const W = { network: "testnet", genesisHash: TN };
const PROVIDERS_HASH = expectedProvidersHash([{ network: "mainnet", allow: MAINNET_PROFILE.providerAllowlist }, { network: "testnet", allow: TESTNET_PROFILE.providerAllowlist }]);
const HOLDER = { holderUser: PG_URL ? decodeURIComponent(new URL(PG_URL).username) : "postgres" };
const COMMIT = "0123456789abcdef0123456789abcdef01234567";
const sha = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");

function poolAs(role: string, pw: string, base: string): pg.Pool {
  const u = new URL(base);
  u.username = role;
  u.password = pw;
  const p = new pg.Pool({ connectionString: u.toString(), max: 2 });
  p.on("error", () => undefined);
  return p;
}

/** A fake release dir named after COMMIT's prefix + a pin file owned by us. */
function fakeRelease() {
  const base = mkdtempSync(path.join(os.tmpdir(), "mr-pin-"));
  const root = path.join(base, COMMIT.slice(0, 7));
  mkdirSync(path.join(root, "deploy"), { recursive: true });
  mkdirSync(path.join(root, "node_modules/x"), { recursive: true });
  writeFileSync(path.join(root, "README.md"), "hello\n");
  writeFileSync(path.join(root, "node_modules/x/i.js"), "1");
  const manifest = path.join(root, "deploy/integrity-manifest.json");
  writeFileSync(manifest, '{"m":1}\n');
  const mSha = sha(readFileSync(manifest));
  const sdFix = { unitDir: path.join(base, "systemd"), envDir: path.join(base, "etc-mr"), expectedUnits: [] as string[] };
  mkdirSync(sdFix.unitDir, { mode: 0o755 });
  mkdirSync(sdFix.envDir, { mode: 0o755 });
  chmodSync(sdFix.unitDir, 0o755);
  chmodSync(sdFix.envDir, 0o755);
  const pinPath = path.join(base, "release-pin");
  writeFileSync(pinPath, formatReleasePin({ commit: COMMIT, treeSha256: releaseTreeHash(root).hash, depsSha256: releaseDepsHash(root).hash, manifestSha256: mSha, systemdSha256: systemdState({ ...sdFix, uid: process.getuid!() }).hash }));
  chmodSync(pinPath, 0o644);
  const check = (o: { env?: Record<string, string>; pinned?: string } = {}) =>
    releasePinReasons({ env: o.env ?? { NETWORK: "testnet" }, root, manifestPath: manifest, pinnedSha256: o.pinned ?? mSha, pinPath, ownerUid: process.getuid!(), systemd: sdFix });
  return { base, root, manifest, mSha, pinPath, check };
}

describe("R28-P3-1 release pin", () => {
  it("a matching pin is clean; node_modules is hashed separately (R29-P3-1)", () => {
    const r = fakeRelease();
    expect(r.check()).toEqual({ reasons: [], commit: COMMIT });
    writeFileSync(path.join(r.root, "node_modules/x/i.js"), "2");
    expect(r.check().reasons).toEqual([expect.stringMatching(/installed dependencies hash .* differs from the pin/)]);
  });
  it("a changed / added file in the release alerts", () => {
    const r = fakeRelease();
    writeFileSync(path.join(r.root, "README.md"), "evil\n");
    expect(r.check().reasons).toEqual([expect.stringMatching(/release tree hash .* differs from the pin/)]);
    writeFileSync(path.join(r.root, "README.md"), "hello\n");
    writeFileSync(path.join(r.root, "extra.js"), "x");
    expect(r.check().reasons).toEqual([expect.stringMatching(/release tree hash/)]);
  });
  it("manifest + code pin edited together still alerts (pin file disagrees)", () => {
    const r = fakeRelease();
    writeFileSync(r.manifest, '{"m":2}\n');
    const reasons = r.check({ pinned: sha(readFileSync(r.manifest)) }).reasons;
    expect(reasons).toEqual(expect.arrayContaining([expect.stringMatching(/manifest sha256 .* in the pin differs from the code pin/), expect.stringMatching(/deployed manifest sha256/), expect.stringMatching(/release tree hash/)]));
  });
  it("missing, malformed, writable or foreign pins alert; the override is refused on mainnet", () => {
    const r = fakeRelease();
    chmodSync(r.pinPath, 0o666);
    expect(r.check().reasons).toEqual([expect.stringMatching(/must be owned by uid .* not group\/other writable/)]);
    chmodSync(r.pinPath, 0o644);
    expect(releasePinReasons({ env: {}, root: r.root, manifestPath: r.manifest, pinnedSha256: r.mSha, pinPath: r.pinPath, ownerUid: 0 === process.getuid!() ? 12345 : 0 }).reasons)
      .toEqual([expect.stringMatching(/must be owned by uid/)]);
    writeFileSync(r.pinPath, "commit=abc\n");
    expect(r.check().reasons).toEqual([expect.stringMatching(/malformed/)]);
    expect(releasePinReasons({ env: {}, root: r.root, manifestPath: r.manifest, pinnedSha256: r.mSha, pinPath: path.join(r.base, "nope"), ownerUid: process.getuid!() }).reasons)
      .toEqual([expect.stringMatching(/missing or unreadable/)]);
    expect(releasePinReasons({ env: { NETWORK: "mainnet", MONITOR_RELEASE_PIN: r.pinPath }, root: r.root, manifestPath: r.manifest, pinnedSha256: r.mSha }).reasons)
      .toEqual([expect.stringMatching(/MONITOR_RELEASE_PIN is refused/)]);
  });
  it("a release dir that is not the pinned commit alerts", () => {
    const r = fakeRelease();
    writeFileSync(r.pinPath, formatReleasePin({ ...parseReleasePin(readFileSync(r.pinPath, "utf8"))!, commit: "f".repeat(40) }));
    expect(r.check().reasons).toEqual([expect.stringMatching(/is not the pinned commit/)]);
  });
  it("runMonitor pages + exits 2 on a release pin reason", async () => {
    const r = fakeRelease();
    writeFileSync(path.join(r.root, "README.md"), "evil\n");
    const lines: string[] = [];
    const res = await runMonitor({
      env: { MONITOR_HEALTH_URLS: "https://h.example/health" }, store: "s", olderThanMin: 30,
      stale: async () => ({ pending: 0, ambiguous: 0, oldestAgeMs: null }), release: () => r.check(),
      fetchImpl: (async () => new Response("ok")) as unknown as typeof fetch, err: (l) => lines.push(l), log: (l) => lines.push(l),
    });
    expect(res.exitCode).toBe(2);
    expect(res.reasons).toEqual([expect.stringMatching(/^release pin: release tree hash/)]);
  });
  it("`spend release-pin` over this checkout's tracked files gives the same tree hash as releaseTreeHash", async () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "mr-arch-"));
    const sdDir = mkdtempSync(path.join(os.tmpdir(), "mr-arch-sd-"));
    chmodSync(sdDir, 0o755);
    await run("sh", ["-c", `git -C '${ROOT}' ls-files -z | (cd '${ROOT}' && xargs -0 tar -cf -) | tar -xf - -C '${dir}'`]);
    const { stdout } = await run(path.join(ROOT, "node_modules/.bin/tsx"), [path.join(ROOT, "packages/storage/src/spend-cli.ts"), "release-pin", "--dir", dir, "--commit", COMMIT, "--systemd-dir", sdDir, "--env-dir", sdDir], { env: { PATH: process.env.PATH, STATE_ENV_FILE: "/dev/null" } });
    const pin = parseReleasePin(stdout)!;
    expect(pin).toMatchObject({ commit: COMMIT, manifestSha256: INTEGRITY_MANIFEST_SHA256, treeSha256: releaseTreeHash(dir).hash });
    expect(sha(readFileSync(DEFAULT_MANIFEST_PATH))).toBe(INTEGRITY_MANIFEST_SHA256);
  }, 60_000);
});

describe.skipIf(!PG_URL)("R28 [postgres]", () => {
  async function hostDb(tag: string) {
    const admin = await getPool();
    const db = `mr_r28_${uid(tag).replace(/-/g, "_")}`;
    await admin.query("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mr_owner') THEN CREATE ROLE mr_owner; END IF; END $$");
    await admin.query("ALTER ROLE mr_owner LOGIN PASSWORD 't-own-pw' NOSUPERUSER");
    await admin.query(`CREATE DATABASE ${db} OWNER mr_owner`);
    const url = PG_URL!.replace(/\/[^/]*$/, `/${db}`);
    const own = poolAs("mr_owner", "t-own-pw", url);
    await migratePostgres(own, { network: "testnet", verifyNetwork: async (p: { caip2: string }) => ({ genesisHash: p.caip2.slice(9) }) });
    await own.end();
    const roleSql = () => run("psql", ["-X", "-q", "-v", "ON_ERROR_STOP=1", "-v", "pw=t-rec-pw", "-v", "mon_pw=t-mon-pw", "-v", "rel_pw=t-rel-pw", "-v", "admin_pw=t-adm-pw", "-d", url, "-f", SQL]);
    await roleSql();
    const sup = new pg.Pool({ connectionString: url, max: 3 });
    sup.on("error", () => undefined);
    return {
      url, sup, db, roleSql,
      cleanup: async () => {
        await sup.end();
        await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`);
        await admin.query("DROP OWNED BY mr_admin CASCADE").catch(() => undefined);
        await admin.query("DROP ROLE IF EXISTS mr_admin");
        await admin.query("DROP ROLE IF EXISTS mr_owner");
      },
    };
  }

  it("R28-P3-2: no stats membership, no foreign query text; holders only via the definer function (mr_monitor only)", async () => {
    const h = await hostDb("fn");
    const mon = poolAs("mr_monitor", "t-mon-pw", h.url);
    const rel = poolAs("mr_release", "t-rel-pw", h.url);
    const c = await h.sup.connect();
    try {
      expect((await h.sup.query("SELECT count(*)::int AS n FROM pg_auth_members WHERE member = 'mr_monitor'::regrole")).rows[0].n).toBe(0);
      const f = (await h.sup.query(`SELECT ow.rolsuper, p.prosecdef, p.proconfig, p.proacl::text AS acl FROM pg_proc p JOIN pg_roles ow ON ow.oid = p.proowner
                                    WHERE p.oid = 'public.mr_window_lock_holders()'::regprocedure`)).rows[0];
      expect(f).toMatchObject({ rolsuper: true, prosecdef: true, proconfig: ["search_path=pg_catalog, pg_temp"] });
      expect(f.acl).toMatch(/mr_monitor=X\//);
      expect(f.acl).not.toMatch(/(^|[{,])=X/); // no PUBLIC
      // a postgres session doing something secret-looking while holding the lock
      await c.query("SET application_name = 'mr-admin-window'");
      await c.query("SELECT pg_advisory_lock(26026, 1)");
      const q = (await mon.query("SELECT query FROM pg_stat_activity WHERE pid = $1", [(await c.query("SELECT pg_backend_pid() AS p")).rows[0].p])).rows[0];
      expect(q?.query ?? "<insufficient privilege>").toBe("<insufficient privilege>");
      const rows = (await mon.query("SELECT * FROM public.mr_window_lock_holders()")).rows;
      expect(rows).toHaveLength(1);
      expect(Object.keys(rows[0]).sort()).toEqual(["application_name", "backend_start", "pid", "usename"]);
      expect(rows[0].backend_start).not.toBeNull();
      const i = await integrityStatus(mon, HOLDER);
      expect(i.windowLockHeld).toBe(true);
      expect(i.windowLockHolders![0]!.ageS).not.toBeNull();
      await expect(rel.query("SELECT * FROM public.mr_window_lock_holders()")).rejects.toThrow(/permission denied/);
      await c.query("SELECT pg_advisory_unlock(26026, 1)");
      // clean against the manifest
      const m = { ...loadIntegrityManifest({}), providersHash: PROVIDERS_HASH };
      expect(integrityReasons(await integrityStatus(mon, HOLDER), W, EXPECTED_MR_TRIGGERS, m)).toEqual([]);
      // re-granting it to PUBLIC, or replacing the body, is drift
      await h.sup.query("GRANT EXECUTE ON FUNCTION public.mr_window_lock_holders() TO PUBLIC");
      expect(integrityReasons(await integrityStatus(mon, HOLDER), W, EXPECTED_MR_TRIGGERS, m)).toEqual([expect.stringMatching(/^integrity: ACL drift/)]);
      await h.roleSql();
      expect(integrityReasons(await integrityStatus(mon, HOLDER), W, EXPECTED_MR_TRIGGERS, m)).toEqual([]);
      // a monitor that lost EXECUTE fails (closed): the integrity query errors
      await h.sup.query("REVOKE EXECUTE ON FUNCTION public.mr_window_lock_holders() FROM mr_monitor");
      await expect(integrityStatus(mon, HOLDER)).rejects.toThrow(/permission denied/);
    } finally {
      c.release();
      await mon.end();
      await rel.end();
      await h.cleanup();
    }
  }, 60_000);

  it("R28-P3-3: role settings (global or per-database) and connection-limit changes on app roles / owner are drift; the role SQL clears them", async () => {
    const h = await hostDb("cfg");
    const mon = poolAs("mr_monitor", "t-mon-pw", h.url);
    const m = { ...loadIntegrityManifest({}), providersHash: PROVIDERS_HASH };
    const reasons = async () => integrityReasons(await integrityStatus(mon, HOLDER), W, EXPECTED_MR_TRIGGERS, m);
    try {
      expect(await reasons()).toEqual([]);
      for (const stmt of [
        "ALTER ROLE mr_demo_api SET search_path = evil",
        `ALTER ROLE mr_console IN DATABASE ${h.db} SET search_path = evil`,
        "ALTER ROLE mr_owner SET statement_timeout = 0",
        "ALTER ROLE mr_owner CONNECTION LIMIT 5",
        "ALTER ROLE mr_bridge CONNECTION LIMIT 1000",
        "ALTER ROLE mr_monitor SET log_statement = 'none'",
      ]) {
        await h.sup.query(stmt);
        expect(await reasons(), stmt).toEqual([expect.stringMatching(/^integrity: role flag \/ membership drift/)]);
        await h.roleSql(); // clears / re-pins
        expect(await reasons(), `after role SQL: ${stmt}`).toEqual([]);
      }
      const lim = (await h.sup.query("SELECT rolname, rolconnlimit FROM pg_roles WHERE rolname IN ('mr_demo_api','mr_console','mr_bridge','mr_owner') ORDER BY 1")).rows;
      expect(lim.map((r) => r.rolconnlimit)).toEqual([40, 40, 40, 40]);
    } finally {
      await mon.end();
      await h.cleanup();
    }
  }, 120_000);
  it("R29-P3-2: ALTER DATABASE SET and ALTER ROLE ALL [IN DATABASE] SET are drift; the role SQL resets them", async () => {
    const h = await hostDb("dbset");
    const mon = poolAs("mr_monitor", "t-mon-pw", h.url);
    const m = { ...loadIntegrityManifest({}), providersHash: PROVIDERS_HASH };
    const reasons = async () => integrityReasons(await integrityStatus(mon, HOLDER), W, EXPECTED_MR_TRIGGERS, m);
    try {
      expect(await reasons()).toEqual([]);
      for (const stmt of [
        `ALTER DATABASE ${h.db} SET search_path = evil`,
        `ALTER ROLE ALL IN DATABASE ${h.db} SET statement_timeout = 0`,
        "ALTER ROLE ALL SET lock_timeout = 0",
      ]) {
        await h.sup.query(stmt);
        expect(await reasons(), stmt).toEqual([expect.stringMatching(/^integrity: role flag \/ membership drift/)]);
        const out = await h.roleSql();
        expect(out.stderr, stmt).toMatch(/R29-P3-2: clearing/);
        expect(out.stderr).not.toMatch(/evil|= ?0/);
        expect(await reasons(), `after role SQL: ${stmt}`).toEqual([]);
      }
      expect((await h.sup.query("SELECT count(*)::int AS n FROM pg_db_role_setting WHERE setrole = 0 AND setdatabase IN (0, (SELECT oid FROM pg_database WHERE datname = current_database()))")).rows[0].n).toBe(0);
    } finally {
      await mon.end();
      await h.cleanup();
    }
  }, 120_000);
});

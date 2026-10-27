/**
 * internal reviewer run 30 (no database needed):
 *  - R30-P3-2: deps hash skips pnpm's volatile metadata (two clean installs of one lockfile
 *    hash identical), a symlinked node_modules is refused, `spend release-pin --deps-sha256`
 *    refuses a host install that differs from the off-host one; `spend deps-hash` prints it.
 *  - R30-P3-3: the pin covers the mandaterail-* units, drop-ins and env-file owner/modes;
 *    a tsx service without TSX_DISABLE_CACHE=1, a writable unit, an open env file, a missing
 *    expected unit or any change after deploy alerts; the repo's units disable the tsx cache.
 * R30-P3-1 (migrate session) is in r30-migrate.test.ts; R30-P3-4 in apps/console + apps/web.
 */
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, symlinkSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { formatReleasePin, releaseDepsHash, releasePinReasons, releaseTreeHash, systemdState } from "./release-pin.js";

const run = promisify(execFile);
const COMMIT = "89abcdef0123456789abcdef0123456789abcdef";
const ROOT = path.resolve(__dirname, "../../..");
const sha = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");
const me = () => process.getuid!();
const UNIT = "[Service]\nUser=mandaterail\nEnvironment=TSX_DISABLE_CACHE=1\nExecStart=/usr/bin/node /opt/mandaterail/current/node_modules/tsx/dist/cli.mjs src/index.ts\n";

function fixture() {
  const base = mkdtempSync(path.join(os.tmpdir(), "mr-r30-"));
  chmodSync(base, 0o755);
  const root = path.join(base, COMMIT.slice(0, 7));
  mkdirSync(path.join(root, "deploy"), { recursive: true });
  mkdirSync(path.join(root, "node_modules/.pnpm/x@1/node_modules/x"), { recursive: true });
  writeFileSync(path.join(root, "node_modules/.pnpm/x@1/node_modules/x/index.js"), "1");
  writeFileSync(path.join(root, "node_modules/.modules.yaml"), "prunedAt: Thu, 15 Oct 2026 21:00:00 GMT\n");
  writeFileSync(path.join(root, "deploy/integrity-manifest.json"), readFileSync(path.join(ROOT, "deploy/integrity-manifest.json")));
  const unitDir = path.join(base, "systemd"), envDir = path.join(base, "etc-mr");
  mkdirSync(unitDir);
  mkdirSync(envDir);
  chmodSync(unitDir, 0o755);
  chmodSync(envDir, 0o755);
  writeFileSync(path.join(unitDir, "mandaterail-demo-api.service"), UNIT, { mode: 0o644 });
  writeFileSync(path.join(envDir, "state-demo-api.env"), "X=1\n", { mode: 0o600 });
  writeFileSync(path.join(envDir, "common.env"), "X=1\n", { mode: 0o640 });
  const sd = { unitDir, envDir, expectedUnits: ["mandaterail-demo-api.service"] };
  const manifest = path.join(root, "deploy/integrity-manifest.json");
  const pinPath = path.join(base, "release-pin");
  const write = () => {
    writeFileSync(pinPath, formatReleasePin({ commit: COMMIT, treeSha256: releaseTreeHash(root).hash, depsSha256: releaseDepsHash(root).hash, manifestSha256: sha(readFileSync(manifest)), systemdSha256: systemdState({ ...sd, uid: me() }).hash }));
    chmodSync(pinPath, 0o644);
  };
  write();
  const check = () => releasePinReasons({ env: { NETWORK: "testnet" }, root, manifestPath: manifest, pinnedSha256: sha(readFileSync(manifest)), pinPath, ownerUid: me(), systemd: sd });
  return { base, root, unitDir, envDir, sd, check, write };
}

describe("R30-P3-2 dependencies", () => {
  it("pnpm metadata (.modules.yaml) is not hashed; real files are", () => {
    const f = fixture();
    const h = releaseDepsHash(f.root).hash;
    writeFileSync(path.join(f.root, "node_modules/.modules.yaml"), "prunedAt: later\nstoreDir: /elsewhere\n");
    expect(releaseDepsHash(f.root).hash).toBe(h);
    writeFileSync(path.join(f.root, "node_modules/.pnpm/x@1/node_modules/x/.modules.yaml"), "x"); // only top-level metadata is skipped
    expect(releaseDepsHash(f.root).hash).not.toBe(h);
  });
  it("a symlinked node_modules (root or nested) is refused", () => {
    const f = fixture();
    expect(f.check().reasons).toEqual([]);
    mkdirSync(path.join(f.root, "packages/storage"), { recursive: true });
    symlinkSync(path.join(f.root, "node_modules"), path.join(f.root, "packages/storage/node_modules"));
    expect(() => releaseDepsHash(f.root)).toThrow(/packages\/storage\/node_modules is a symlink/);
    expect(f.check().reasons).toContainEqual(expect.stringMatching(/node_modules is a symlink \(refused/));
  });
  it("`spend release-pin --deps-sha256` refuses a different install; `spend deps-hash` prints the hash", async () => {
    const f = fixture();
    const tsx = path.join(ROOT, "node_modules/.bin/tsx"), cli = path.join(ROOT, "packages/storage/src/spend-cli.ts");
    const env = { PATH: process.env.PATH, STATE_ENV_FILE: "/dev/null" };
    const deps = releaseDepsHash(f.root).hash;
    const { stdout } = await run(tsx, [cli, "deps-hash", "--dir", f.root], { env });
    expect(stdout).toContain(`deps_sha256=${deps}`);
    const sdArgs = ["--systemd-dir", f.unitDir, "--env-dir", f.envDir];
    const ok = await run(tsx, [cli, "release-pin", "--dir", f.root, "--commit", COMMIT, "--deps-sha256", deps, ...sdArgs], { env });
    expect(ok.stdout).toContain(`systemd_sha256=${systemdState({ ...f.sd, uid: me() }).hash}`);
    await expect(run(tsx, [cli, "release-pin", "--dir", f.root, "--commit", COMMIT, "--deps-sha256", "e".repeat(64), ...sdArgs], { env })).rejects.toThrow(/differs from --deps-sha256/);
    writeFileSync(path.join(f.unitDir, "mandaterail-console.service"), UNIT.replace("Environment=TSX_DISABLE_CACHE=1\n", ""), { mode: 0o644 });
    await expect(run(tsx, [cli, "release-pin", "--dir", f.root, "--commit", COMMIT, ...sdArgs], { env })).rejects.toThrow(/systemd\/env violations: .*without Environment=TSX_DISABLE_CACHE=1/);
  }, 60_000);
});

describe("R30-P3-3 systemd units, drop-ins, env files", () => {
  it("clean fixture; any unit or drop-in change after deploy alerts", () => {
    const f = fixture();
    expect(f.check().reasons).toEqual([]);
    mkdirSync(path.join(f.unitDir, "mandaterail-demo-api.service.d"));
    chmodSync(path.join(f.unitDir, "mandaterail-demo-api.service.d"), 0o755);
    writeFileSync(path.join(f.unitDir, "mandaterail-demo-api.service.d/evil.conf"), "[Service]\nEnvironment=NODE_OPTIONS=--import=/tmp/x.mjs\n", { mode: 0o644 });
    expect(f.check().reasons).toEqual([expect.stringMatching(/systemd units \/ drop-ins \/ env-file modes hash .* differs from the pin/)]);
    f.write();
    expect(f.check().reasons).toEqual([]);
    writeFileSync(path.join(f.unitDir, "mandaterail-demo-api.service"), UNIT + "# x\n");
    expect(f.check().reasons).toEqual([expect.stringMatching(/hash .* differs from the pin/)]);
  });
  it("rules: tsx without TSX_DISABLE_CACHE=1, writable units, open env files, missing units", () => {
    const f = fixture();
    const v = () => systemdState({ ...f.sd, uid: me() }).violations;
    expect(v()).toEqual([]);
    writeFileSync(path.join(f.unitDir, "mandaterail-demo-api.service"), UNIT.replace("TSX_DISABLE_CACHE=1", "TSX_DISABLE_CACHE=0"));
    expect(v()).toEqual([expect.stringMatching(/demo-api.service runs tsx without Environment=TSX_DISABLE_CACHE=1/)]);
    // a drop-in can supply it
    mkdirSync(path.join(f.unitDir, "mandaterail-demo-api.service.d"));
    chmodSync(path.join(f.unitDir, "mandaterail-demo-api.service.d"), 0o755);
    writeFileSync(path.join(f.unitDir, "mandaterail-demo-api.service.d/r30-tsx.conf"), "[Service]\nEnvironment=TSX_DISABLE_CACHE=1\n", { mode: 0o644 });
    expect(v()).toEqual([]);
    chmodSync(path.join(f.unitDir, "mandaterail-demo-api.service"), 0o664);
    expect(v()).toEqual([expect.stringMatching(/demo-api.service must be owned by uid .* not group\/other writable/)]);
    chmodSync(path.join(f.unitDir, "mandaterail-demo-api.service"), 0o644);
    chmodSync(path.join(f.envDir, "state-demo-api.env"), 0o640);
    expect(v()).toEqual([expect.stringMatching(/state-demo-api.env mode 640 is too open \(0600 max\)/)]);
    chmodSync(path.join(f.envDir, "state-demo-api.env"), 0o600);
    chmodSync(path.join(f.envDir, "common.env"), 0o644);
    expect(v()).toEqual([expect.stringMatching(/common.env mode 644 is too open \(0640 max\)/)]);
    chmodSync(path.join(f.envDir, "common.env"), 0o640);
    expect(systemdState({ ...f.sd, uid: me(), expectedUnits: ["mandaterail-monitor.timer"] }).violations).toEqual(["mandaterail-monitor.timer is missing"]);
  });
  it("an env-file mode change after deploy alerts even within the rules", () => {
    const f = fixture();
    chmodSync(path.join(f.envDir, "common.env"), 0o600);
    expect(f.check().reasons).toEqual([expect.stringMatching(/hash .* differs from the pin/)]);
  });
  it("the repo's tsx units disable the tsx cache", () => {
    const dir = path.join(ROOT, "deploy/systemd");
    for (const n of readdirSync(dir).filter((x) => x.endsWith(".service"))) {
      expect(readFileSync(path.join(dir, n), "utf8"), n).toMatch(/^Environment=TSX_DISABLE_CACHE=1$/m);
    }
  });
});

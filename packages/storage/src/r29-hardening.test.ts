/**
 * R29 hardening (no database needed):
 *  - R29-P3-1: installed dependencies (every node_modules, nested ones too) are part of
 *    the pin (deps_sha256); any release path not owned by the expected uid or
 *    group/other writable alerts; the CLI prints deps_sha256 and refuses a tree hash that
 *    differs from the git-archive one.
 *  - R29 optional: manifest pinned by sha256; the pin file is opened with O_NOFOLLOW.
 * The R29-P3-2 database-wide settings checks are in r29-dbsettings.test.ts.
 */
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { formatReleasePin, parseReleasePin, releaseDepsHash, releaseOwnershipViolations, releasePinReasons, releaseTreeHash, systemdState } from "./release-pin.js";

const run = promisify(execFile);
const COMMIT = "0123456789abcdef0123456789abcdef01234567";
const sha = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");
const ROOT = path.resolve(__dirname, "../../..");

function fakeRelease() {
  const base = mkdtempSync(path.join(os.tmpdir(), "mr-r29-"));
  chmodSync(base, 0o755);
  const root = path.join(base, COMMIT.slice(0, 7));
  mkdirSync(path.join(root, "deploy"), { recursive: true });
  mkdirSync(path.join(root, "node_modules/.pnpm/x@1/node_modules/x"), { recursive: true });
  mkdirSync(path.join(root, "packages/storage/node_modules"), { recursive: true });
  writeFileSync(path.join(root, "node_modules/.pnpm/x@1/node_modules/x/index.js"), "1");
  symlinkSync(".pnpm/x@1/node_modules/x", path.join(root, "node_modules/x"));
  symlinkSync("../../../node_modules/.pnpm/x@1/node_modules/x", path.join(root, "packages/storage/node_modules/x"));
  const manifest = path.join(root, "deploy/integrity-manifest.json");
  writeFileSync(manifest, '{"m":1}\n');
  const sdFix = { unitDir: path.join(base, "systemd"), envDir: path.join(base, "etc-mr"), expectedUnits: [] as string[] };
  mkdirSync(sdFix.unitDir, { mode: 0o755 });
  mkdirSync(sdFix.envDir, { mode: 0o755 });
  chmodSync(sdFix.unitDir, 0o755);
  chmodSync(sdFix.envDir, 0o755);
  const pinPath = path.join(base, "release-pin");
  const write = () => {
    writeFileSync(pinPath, formatReleasePin({ commit: COMMIT, treeSha256: releaseTreeHash(root).hash, depsSha256: releaseDepsHash(root).hash, manifestSha256: sha(readFileSync(manifest)), systemdSha256: systemdState({ ...sdFix, uid: process.getuid!() }).hash }));
    chmodSync(pinPath, 0o644);
  };
  write();
  const check = () => releasePinReasons({ env: { NETWORK: "testnet" }, root, manifestPath: manifest, pinnedSha256: sha(readFileSync(manifest)), pinPath, ownerUid: process.getuid!(), systemd: sdFix });
  return { base, root, pinPath, check, write, sdFix };
}

describe("R29-P3-1 dependencies + ownership", () => {
  it("clean pin; edits, additions and relinks inside node_modules (root or nested) alert", () => {
    const r = fakeRelease();
    expect(r.check()).toEqual({ reasons: [], commit: COMMIT });
    writeFileSync(path.join(r.root, "node_modules/.pnpm/x@1/node_modules/x/index.js"), "evil");
    expect(r.check().reasons).toEqual([expect.stringMatching(/installed dependencies hash/)]);
    r.write();
    mkdirSync(path.join(r.root, "node_modules/.pnpm/empty"));
    expect(r.check().reasons).toEqual([expect.stringMatching(/installed dependencies hash/)]);
    r.write();
    writeFileSync(path.join(r.root, "packages/storage/node_modules/y.js"), "x");
    expect(r.check().reasons).toEqual([expect.stringMatching(/installed dependencies hash/)]);
  });
  it("tree and deps hashes are independent", () => {
    const r = fakeRelease();
    const t = releaseTreeHash(r.root).hash;
    writeFileSync(path.join(r.root, "node_modules/.pnpm/x@1/node_modules/x/index.js"), "2");
    expect(releaseTreeHash(r.root).hash).toBe(t);
  });
  it("a group/other-writable or foreign-owned path anywhere in the release alerts", () => {
    const r = fakeRelease();
    chmodSync(path.join(r.root, "node_modules/.pnpm/x@1/node_modules/x/index.js"), 0o666);
    expect(r.check().reasons).toEqual([expect.stringMatching(/1 release path\(s\) not owned by uid .* group\/other writable .*index\.js/)]);
    chmodSync(path.join(r.root, "node_modules/.pnpm/x@1/node_modules/x/index.js"), 0o644);
    chmodSync(path.join(r.root, "deploy"), 0o777);
    expect(r.check().reasons).toEqual([expect.stringMatching(/not owned by uid/)]);
    chmodSync(path.join(r.root, "deploy"), 0o755);
    expect(releaseOwnershipViolations(r.root, process.getuid!() + 4242).count).toBeGreaterThan(5);
  });
  it("a group/other-writable ancestor without the sticky bit alerts; a sticky one (/tmp) does not", () => {
    const r = fakeRelease();
    expect(releaseOwnershipViolations(r.root, process.getuid!()).count).toBe(0);
    chmodSync(r.base, 0o777);
    expect(releaseOwnershipViolations(r.root, process.getuid!()).examples).toEqual([r.base]);
    chmodSync(r.base, 0o1777);
    expect(releaseOwnershipViolations(r.root, process.getuid!()).count).toBe(0);
  });
});

describe("R29 optional: sha256 manifest pin, O_NOFOLLOW", () => {
  it("a symlinked pin is refused", () => {
    const r = fakeRelease();
    const link = path.join(r.base, "pin-link");
    symlinkSync(r.pinPath, link);
    const reasons = releasePinReasons({ env: {}, root: r.root, manifestPath: path.join(r.root, "deploy/integrity-manifest.json"), pinnedSha256: "0".repeat(64), pinPath: link, ownerUid: process.getuid!() }).reasons;
    expect(reasons).toEqual([expect.stringMatching(/is a symlink \(refused, O_NOFOLLOW\)/)]);
  });
  it("an old md5-format pin is malformed (deploy must write the new format)", () => {
    expect(parseReleasePin(`commit=${COMMIT}\ntree_sha256=${"a".repeat(64)}\nmanifest_md5=${"b".repeat(32)}\n`)).toBeNull();
  });
  it("`spend release-pin` prints deps_sha256 and refuses a mismatching --tree-sha256", async () => {
    const r = fakeRelease();
    // the CLI requires the real manifest; copy it in
    writeFileSync(path.join(r.root, "deploy/integrity-manifest.json"), readFileSync(path.join(ROOT, "deploy/integrity-manifest.json")));
    const tsx = path.join(ROOT, "node_modules/.bin/tsx"), cli = path.join(ROOT, "packages/storage/src/spend-cli.ts");
    const env = { PATH: process.env.PATH, STATE_ENV_FILE: "/dev/null" };
    const tree = releaseTreeHash(r.root).hash;
    const { stdout } = await run(tsx, [cli, "release-pin", "--dir", r.root, "--commit", COMMIT, "--tree-sha256", tree, "--systemd-dir", r.sdFix.unitDir, "--env-dir", r.sdFix.envDir], { env });
    expect(parseReleasePin(stdout)).toMatchObject({ commit: COMMIT, treeSha256: tree, depsSha256: releaseDepsHash(r.root).hash });
    await expect(run(tsx, [cli, "release-pin", "--dir", r.root, "--commit", COMMIT, "--tree-sha256", "f".repeat(64), "--systemd-dir", r.sdFix.unitDir, "--env-dir", r.sdFix.envDir], { env })).rejects.toThrow(/differs from --tree-sha256/);
  }, 60_000);
});

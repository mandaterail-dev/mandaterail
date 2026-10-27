/**
 * internal reviewer run 31 (no database needed):
 *  - R31-P3-1: systemd_sha256 covers the EFFECTIVE `systemctl show` values (FragmentPath,
 *    DropInPaths, Environment, EnvironmentFiles, ExecStart without runtime fields) plus the
 *    content/owner/mode of every file they point to (node binary included) and the global
 *    service.d drop-ins in the /etc, /run, control and generator dirs.
 *  - R31-P3-2: volatile pnpm names are skipped only as regular files; anything else fails.
 *  - R31-P3-3: env-file contents are hashed (unreadable ones via the root attestation).
 * R31-P3-4 is in r31-migrate.test.ts; R31-P3-5 in apps/console.
 */
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { normalizeExec, releaseDepsHash, systemdState, VolatileDepsEntryError } from "./release-pin.js";

const me = () => process.getuid!();
const sha = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");
const UNIT = "[Service]\nEnvironment=TSX_DISABLE_CACHE=1\nExecStart=/usr/bin/node x/tsx src/index.ts\n";

function fx() {
  const base = mkdtempSync(path.join(os.tmpdir(), "mr-r31-"));
  chmodSync(base, 0o755);
  const d = (p: string) => { const a = path.join(base, p); mkdirSync(a, { recursive: true }); chmodSync(a, 0o755); return a; };
  const unitDir = d("etc-systemd"), envDir = d("etc-mr"), runDir = d("run-systemd"), bin = d("bin");
  const f = (p: string, body: string, mode = 0o644) => { writeFileSync(p, body, { mode }); chmodSync(p, mode); return p; };
  const unit = f(path.join(unitDir, "mandaterail-demo-api.service"), UNIT);
  const env = f(path.join(envDir, "state-demo-api.env"), "SECRET=1\n", 0o600);
  const node = f(path.join(bin, "node"), "ELF-v22", 0o755);
  let start = "start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0";
  let extraDropIns = "";
  let environment = "STATE_ENV_FILE=/dev/null TSX_DISABLE_CACHE=1";
  const show = (u: string) => u !== "mandaterail-demo-api.service" ? null :
    `FragmentPath=${unit}\nDropInPaths=${extraDropIns}\nExecStart={ path=${node} ; argv[]=${node} x/tsx src/index.ts ; ignore_errors=no ; ${start} }\nEnvironment=${environment}\nEnvironmentFiles=${env} (ignore_errors=no)\n`;
  const sd = { unitDir, envDir, expectedUnits: ["mandaterail-demo-api.service"], show, controlDirs: [unitDir, runDir, path.join(base, "absent")], attestationPath: path.join(base, "attest") };
  const state = () => systemdState({ ...sd, uid: me() });
  return { base, unitDir, envDir, runDir, node, env, unit, sd, state, f, d,
    setStart: (s: string) => { start = s; }, setDropIns: (s: string) => { extraDropIns = s; }, setEnv: (s: string) => { environment = s; } };
}

describe("R31-P3-1 effective systemd configuration", () => {
  it("is stable across runs (runtime ExecStart fields ignored)", () => {
    const x = fx();
    const h = x.state();
    expect(h.violations).toEqual([]);
    x.setStart("start_time=[Fri 2026-10-16 05:39:15 CST] ; stop_time=[Fri] ; pid=67397 ; code=exited ; status=0");
    expect(x.state().hash).toBe(h.hash);
    expect(normalizeExec("{ path=/usr/bin/node ; argv[]=/usr/bin/node a ; ignore_errors=no ; pid=1 ; status=0 }")).toEqual({ norm: "{ path=/usr/bin/node ; argv[]=/usr/bin/node a ; ignore_errors=no }", paths: ["/usr/bin/node"] });
  });
  it("a global service.d drop-in (NODE_OPTIONS) changes the hash", () => {
    const x = fx();
    const h = x.state().hash;
    const g = x.d("run-systemd/service.d");
    const conf = x.f(path.join(g, "evil.conf"), "[Service]\nEnvironment=NODE_OPTIONS=--require=/tmp/x.js\n");
    expect(x.state().hash).not.toBe(h);
    // and the effective values systemd reports change too
    const h2 = x.state().hash;
    x.setDropIns(conf);
    x.setEnv("STATE_ENV_FILE=/dev/null TSX_DISABLE_CACHE=1 NODE_OPTIONS=--require=/tmp/x.js");
    expect(x.state().hash).not.toBe(h2);
  });
  it("a prefix drop-in dir (mandaterail-.service.d) in a control dir changes the hash", () => {
    const x = fx();
    const h = x.state().hash;
    x.f(path.join(x.d("run-systemd/mandaterail-.service.d"), "a.conf"), "[Service]\n");
    expect(x.state().hash).not.toBe(h);
  });
  it("the node binary's content and mode are pinned; writable files are violations", () => {
    const x = fx();
    const h = x.state().hash;
    writeFileSync(x.node, "ELF-evil");
    expect(x.state().hash).not.toBe(h);
    chmodSync(x.node, 0o775);
    expect(x.state().violations).toEqual([expect.stringMatching(/bin\/node must be owned by uid .* not group\/other writable/)]);
  });
  it("a symlinked binary is recorded by target and the target hashed", () => {
    const x = fx();
    const h = x.state().hash;
    const real = x.f(path.join(x.base, "bin/node-real"), "ELF-v22", 0o755);
    const link = path.join(x.base, "bin/node2");
    symlinkSync(real, link);
    x.setStart(""); // unchanged ExecStart path; add a second binary via drop-in path list
    x.setDropIns(link);
    expect(x.state().hash).not.toBe(h);
  });
  it("systemctl show failing is a violation", () => {
    const x = fx();
    expect(systemdState({ ...x.sd, uid: me(), expectedUnits: ["mandaterail-demo-api.service", "mandaterail-monitor.timer"] }).violations).toContain("systemctl show mandaterail-monitor.timer failed");
  });
});

describe("R31-P3-3 env-file contents", () => {
  it("a content change with the same mode changes the hash", () => {
    const x = fx();
    const h = x.state().hash;
    writeFileSync(x.env, "SECRET=2\n");
    expect(x.state().hash).not.toBe(h);
  });
  it("unreadable files use the root attestation; missing attestation is a violation", () => {
    if (me() === 0) return; // root reads everything
    const x = fx();
    const h = x.state().hash;
    chmodSync(x.env, 0o000);
    expect(x.state().violations.join("\n")).toMatch(/state-demo-api.env content is unreadable/);
    writeFileSync(x.sd.attestationPath, `${sha("SECRET=1\n")}  ${x.env}\n`, { mode: 0o644 });
    chmodSync(x.env, 0o600);
    const readable = x.state().hash;
    chmodSync(x.env, 0o000);
    // attested sha equals the direct sha, but mode 000 differs from 600 -> only meta differs
    expect(x.state().violations).toEqual([]);
    chmodSync(x.env, 0o600);
    expect(x.state().hash).toBe(readable);
    expect(readable).toBe(h);
    // a group/other-writable attestation is ignored
    chmodSync(x.sd.attestationPath, 0o666);
    chmodSync(x.env, 0o000);
    expect(x.state().violations.join("\n")).toMatch(/unreadable/);
    chmodSync(x.env, 0o600);
  });
  it("the hash never contains the secret", () => {
    const x = fx();
    expect(JSON.stringify(x.state())).not.toContain("SECRET");
  });
});

describe("R31-P3-2 volatile deps names", () => {
  const rel = () => {
    const base = mkdtempSync(path.join(os.tmpdir(), "mr-r31d-"));
    mkdirSync(path.join(base, "node_modules/x"), { recursive: true });
    writeFileSync(path.join(base, "node_modules/x/index.js"), "1");
    return base;
  };
  it("a regular file is skipped", () => {
    const b = rel();
    const h = releaseDepsHash(b).hash;
    writeFileSync(path.join(b, "node_modules/.modules.yaml"), "x");
    expect(releaseDepsHash(b).hash).toBe(h);
  });
  it("a directory or symlink under a volatile name is refused", () => {
    const b = rel();
    mkdirSync(path.join(b, "node_modules/.modules.yaml"));
    writeFileSync(path.join(b, "node_modules/.modules.yaml/evil.js"), "x");
    expect(() => releaseDepsHash(b)).toThrow(VolatileDepsEntryError);
    const c = rel();
    symlinkSync("/etc/passwd", path.join(c, "node_modules/.pnpm-workspace-state.json"));
    expect(() => releaseDepsHash(c)).toThrow(/not a regular file/);
  });
});

describe("repo monitor unit attests root-only files", () => {
  it("has the root ExecStartPre", () => {
    const u = readFileSync(path.resolve(__dirname, "../../../deploy/systemd/mandaterail-monitor.service"), "utf8");
    expect(u).toMatch(/^ExecStartPre=\+\/bin\/sh -c .*install -d -o root -g root -m 0755 \$d.*sha256sum \/etc\/mandaterail\/\*\.env .*mv -f \$d\/root-sha256\.tmp \$d\/root-sha256'$/m);
    expect(u).toMatch(/d=\/run\/mandaterail-attest;/);
    // R32-P3-2: no RuntimeDirectory (it would be owned by the monitor user)
    expect(u).not.toMatch(/^RuntimeDirectory=/m);
  });
});

describe("R32 hardening", () => {
  it("R32-P3-1: system.conf and system.conf.d/* changes alter the hash", () => {
    const x = fx();
    const conf = x.f(path.join(x.base, "system.conf"), "[Manager]\n");
    const dir = x.d("system.conf.d");
    const st = () => systemdState({ ...x.sd, uid: me(), managerConf: [conf], managerConfDirs: [dir, path.join(x.base, "nope")] });
    const h = st();
    expect(h.violations).toEqual([]);
    writeFileSync(conf, "[Manager]\nDefaultEnvironment=NODE_OPTIONS=--require=/tmp/x.js\n");
    const h2 = st();
    expect(h2.hash).not.toBe(h.hash);
    x.f(path.join(dir, "zz.conf"), "[Manager]\nDefaultEnvironment=A=1\n");
    expect(st().hash).not.toBe(h2.hash);
    chmodSync(dir, 0o777);
    expect(st().violations.join()).toMatch(/not group\/other writable/);
  });
  it("R32-P3-2: an attestation in a group/other-writable dir is ignored", () => {
    const x = fx();
    const adir = x.d("attest-dir");
    const ap = path.join(adir, "root-sha256");
    chmodSync(x.env, 0);
    writeFileSync(ap, `${createHash("sha256").update("SECRET=1\n").digest("hex")}  ${x.env}\n`, { mode: 0o644 });
    const ok = systemdState({ ...x.sd, uid: me(), attestationPath: ap });
    chmodSync(adir, 0o777);
    const bad = systemdState({ ...x.sd, uid: me(), attestationPath: ap });
    chmodSync(x.env, 0o600);
    if (process.getuid?.() === 0) return; // root reads mode-000 files directly
    expect(ok.violations.join()).not.toMatch(/unreadable/);
    expect(bad.violations.join()).toMatch(/unreadable and not in the root attestation/);
  });
});

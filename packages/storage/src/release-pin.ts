/**
 * R28-P3-1 / R29-P3-1: release pin. The deploy writes /etc/mandaterail/release-pin
 * (root:root 0644) with:
 *   - commit           the deployed git commit;
 *   - tree_sha256      hash of the release tree without node_modules, computed from
 *                      `git archive <commit>` on the deploying machine and checked
 *                      identical on the host;
 *   - deps_sha256      (R29-P3-1 / R30-P3-2) hash of every installed node_modules tree
 *                      in the release. Computed OFF the host (the deploying machine) from a
 *                      clean `pnpm install --frozen-lockfile --ignore-scripts` of the
 *                      lockfile at the same absolute path, and the host's install must
 *                      hash identical (`spend release-pin --deps-sha256`); a symlinked
 *                      node_modules is refused;
 *   - manifest_sha256  (R29 optional) sha256 of deploy/integrity-manifest.json;
 *   - systemd_sha256   (R30-P3-3) the mandaterail-* units + drop-ins (content, owner, mode)
 *                      and /etc/mandaterail/*.env (owner, mode); see systemdState().
 * On every run the monitor checks:
 *   - the pin is a regular file (opened with O_NOFOLLOW), owned by root, not
 *     group/other writable;
 *   - the release directory it runs from is named after the pinned commit;
 *   - the manifest's sha256 equals both the pin and INTEGRITY_MANIFEST_SHA256 in code;
 *   - the release tree and the installed dependencies hash to the pin;
 *   - (R29-P3-1) every file and directory of the release, node_modules included, and
 *     every ancestor directory is root-owned and not group/other writable, so the app
 *     user (`mandaterail`, which the monitor runs as) cannot change the checker, its
 *     dependencies or the manifest.
 * Without a signing key, someone who can write root-owned files can still rewrite the
 * pin too; the pinned commit and tree hash can be checked against git from off the host.
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { closeSync, constants as fsc, fstatSync, lstatSync, openSync, readdirSync, readFileSync, readlinkSync, realpathSync, statSync } from "node:fs";
import path from "node:path";

export const DEFAULT_RELEASE_PIN_PATH = "/etc/mandaterail/release-pin";
export interface ReleasePin { commit: string; treeSha256: string; depsSha256: string; manifestSha256: string; systemdSha256: string }
export const DEFAULT_SYSTEMD_DIR = "/etc/systemd/system";
export const DEFAULT_ENV_DIR = "/etc/mandaterail";
/** R30-P3-3: units every host must have (the monitor alerts when one is missing). */
export const EXPECTED_UNITS = [
  "mandaterail-demo-api.service", "mandaterail-ac2-bridge.service", "mandaterail-console.service",
  "mandaterail-monitor.service", "mandaterail-monitor.timer", "mandaterail-reconcile.service", "mandaterail-reconcile.timer",
];

/**
 * R30-P3-3: state of the systemd units, their drop-ins and the env files.
 *  - units: <dir>/mandaterail-*.{service,timer} (regular files, content hashed);
 *  - drop-ins: <dir>/mandaterail-*.{service,timer}.d/*.conf (content hashed);
 *  - env files: <envDir>/*.env, by name + uid + gid + mode only (they are root 0600 /
 *    0640 and the monitor user can't read the secret ones), plus <envDir> itself.
 * hash = sha256 over the sorted lines. violations: anything not root-owned or group/other
 * writable, an env file readable by others (state-*.env: by group too), a symlinked unit /
 * drop-in, a missing expected unit, or a tsx service without Environment=TSX_DISABLE_CACHE=1.
 */
export interface SystemdOpts {
  unitDir?: string;
  envDir?: string;
  uid?: number;
  expectedUnits?: ReadonlyArray<string>;
  /** R31-P3-1: `systemctl show` provider; default systemctlShow when unitDir is the real one, off for fixtures unless given. */
  show?: ((unit: string) => string | null) | false;
  /** R31-P3-1: control dirs (tests); default DEFAULT_CONTROL_DIRS. */
  controlDirs?: ReadonlyArray<string>;
  /** R31-P3-3: root-written sha256sum file for paths the monitor user can't read. */
  attestationPath?: string;
  /** R32-P3-1: systemd manager config files + conf dirs (tests); defaults DEFAULT_MANAGER_CONF / DEFAULT_MANAGER_CONF_DIRS. */
  managerConf?: ReadonlyArray<string>;
  managerConfDirs?: ReadonlyArray<string>;
}
export function systemdState(o: SystemdOpts = {}): { hash: string; entries: number; violations: string[] } {
  const unitDir = o.unitDir ?? DEFAULT_SYSTEMD_DIR, envDir = o.envDir ?? DEFAULT_ENV_DIR, uid = o.uid ?? 0;
  const show = o.show === false ? null : o.show ?? (o.unitDir === undefined || o.unitDir === DEFAULT_SYSTEMD_DIR ? systemctlShow : null);
  const attestPath = o.attestationPath ?? DEFAULT_ROOT_ATTESTATION;
  const attest = readAttestation(attestPath, uid);
  const lines: Line[] = [];
  const v: string[] = [];
  const meta = (st: { uid: number; gid: number; mode: number }) => `${st.uid}:${st.gid}:${(st.mode & 0o7777).toString(8)}`;
  const names = (d: string) => {
    try {
      return readdirSync(d).sort();
    } catch {
      return null;
    }
  };
  const content = new Map<string, string>();
  const unitNames = (names(unitDir) ?? []).filter((n) => /^mandaterail-[a-z0-9-]+\.(service|timer)$/.test(n));
  for (const n of unitNames) {
    const a = path.join(unitDir, n);
    const st = lstatSync(a);
    if (!st.isFile()) { v.push(`${n} is not a regular file`); lines.push([n, `u ? ${n}`]); continue; }
    if (st.uid !== uid || (st.mode & 0o022) !== 0) v.push(`${n} must be owned by uid ${uid} and not group/other writable`);
    const body = readFileSync(a, "utf8");
    content.set(n, body);
    lines.push([n, `u ${createHash("sha256").update(body).digest("hex")} ${meta(st)} ${n}`]);
  }
  for (const n of (names(unitDir) ?? []).filter((x) => /^mandaterail-[a-z0-9-]+\.(service|timer)\.d$/.test(x))) {
    const d = path.join(unitDir, n);
    const dst = lstatSync(d);
    if (!dst.isDirectory()) { v.push(`${n} is not a directory`); continue; }
    if (dst.uid !== uid || (dst.mode & 0o022) !== 0) v.push(`${n} must be owned by uid ${uid} and not group/other writable`);
    lines.push([n, `D - ${meta(dst)} ${n}`]);
    for (const f of names(d) ?? []) {
      const a = path.join(d, f), r = `${n}/${f}`;
      const st = lstatSync(a);
      if (!st.isFile()) { v.push(`${r} is not a regular file`); lines.push([r, `i ? ${r}`]); continue; }
      if (st.uid !== uid || (st.mode & 0o022) !== 0) v.push(`${r} must be owned by uid ${uid} and not group/other writable`);
      const body = readFileSync(a, "utf8");
      if (f.endsWith(".conf")) {
        const unit = n.slice(0, -2);
        content.set(unit, `${content.get(unit) ?? ""}\n${body}`);
      }
      lines.push([r, `i ${createHash("sha256").update(body).digest("hex")} ${meta(st)} ${r}`]);
    }
  }
  for (const u of o.expectedUnits ?? EXPECTED_UNITS) if (!content.has(u)) v.push(`${u} is missing`);
  for (const [u, body] of content) {
    if (u.endsWith(".service") && /tsx/.test(body) && !/^\s*Environment=("?)TSX_DISABLE_CACHE=1\1\s*$/m.test(body)) v.push(`${u} runs tsx without Environment=TSX_DISABLE_CACHE=1`);
  }
  const env = names(envDir);
  if (env === null) v.push(`${envDir} is missing`);
  else {
    const dst = statSync(envDir);
    if (dst.uid !== uid || (dst.mode & 0o022) !== 0) v.push(`${envDir} must be owned by uid ${uid} and not group/other writable`);
    lines.push(["~env", `E - ${meta(dst)} ${envDir}`]);
    for (const n of env.filter((x) => x.endsWith(".env"))) {
      const st = lstatSync(path.join(envDir, n));
      if (!st.isFile()) v.push(`${n} is not a regular file`);
      else if (st.uid !== uid) v.push(`${n} must be owned by uid ${uid}`);
      else if ((st.mode & (n.startsWith("state-") ? 0o077 : 0o027)) !== 0) v.push(`${n} mode ${(st.mode & 0o777).toString(8)} is too open (${n.startsWith("state-") ? "0600" : "0640"} max)`);
      // R31-P3-3: env-file CONTENT is hashed too (sha256 only, never printed). Files the
      // monitor user can't read come from the root-written attestation (see rootAttestation).
      const c = st.isFile() ? fileSha(path.join(envDir, n), attest) : null;
      if (st.isFile() && c === null) v.push(`${n} content is unreadable and not in the root attestation ${attestPath}`);
      lines.push([`~env/${n}`, `e ${c ?? "?"} ${meta(st)} ${n}`]);
    }
  }
  // R31-P3-1: the EFFECTIVE configuration systemd uses (global service.d drop-ins,
  // /run and control dirs, generators, EnvironmentFiles, the ExecStart binary).
  if (show) effectiveState({ units: [...new Set([...unitNames, ...(o.expectedUnits ?? EXPECTED_UNITS)])].sort(), show, dirs: o.controlDirs ?? DEFAULT_CONTROL_DIRS, uid, attest, attestPath, lines, v });
  // R32-P3-1: manager-wide config (DefaultEnvironment=, ManagerEnvironment=, ...) applies to every unit.
  const realHost = o.unitDir === undefined || o.unitDir === DEFAULT_SYSTEMD_DIR;
  if (o.managerConf || o.managerConfDirs || (show && realHost)) managerConfState({ files: o.managerConf ?? (realHost ? DEFAULT_MANAGER_CONF : []), dirs: o.managerConfDirs ?? (realHost ? DEFAULT_MANAGER_CONF_DIRS : []), uid, lines, v });
  return { hash: sortHash(lines), entries: lines.length, violations: v };
}

/** R31-P3-1: dirs systemd reads unit config from (besides unitDir); drop-ins in them are hashed. */
export const DEFAULT_CONTROL_DIRS = [
  "/etc/systemd/system", "/etc/systemd/system.control", "/run/systemd/system", "/run/systemd/system.control",
  "/run/systemd/transient", "/run/systemd/generator", "/run/systemd/generator.early", "/run/systemd/generator.late",
  "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system", "/etc/systemd/system.conf.d",
];
/** R32-P3-1: systemd manager config. */
export const DEFAULT_MANAGER_CONF = ["/etc/systemd/system.conf"];
export const DEFAULT_MANAGER_CONF_DIRS = ["/etc/systemd/system.conf.d", "/run/systemd/system.conf.d", "/usr/local/lib/systemd/system.conf.d", "/usr/lib/systemd/system.conf.d"];
/**
 * R31-P3-1/3: written by the monitor unit's root ExecStartPre (sha256sum format).
 * R32-P3-2: lives in a ROOT-owned dir (not the unit's RuntimeDirectory, which the
 * monitor user owns and could swap the file in); the parent dir is checked too.
 */
export const DEFAULT_ROOT_ATTESTATION = "/run/mandaterail-attest/root-sha256";

function managerConfState(a: { files: ReadonlyArray<string>; dirs: ReadonlyArray<string>; uid: number; lines: Line[]; v: string[] }): void {
  const meta = (st: { uid: number; gid: number; mode: number }) => `${st.uid}:${st.gid}:${(st.mode & 0o7777).toString(8)}`;
  const one = (f: string) => {
    let st;
    try {
      st = lstatSync(f);
    } catch {
      a.lines.push([`~mgr${f}`, `M absent ${f}`]);
      return;
    }
    if (!st.isFile()) { a.v.push(`${f} is not a regular file`); a.lines.push([`~mgr${f}`, `M ? ${meta(st)} ${f}`]); return; }
    if (st.uid !== a.uid || (st.mode & 0o022) !== 0) a.v.push(`${f} must be owned by uid ${a.uid} and not group/other writable`);
    let c = "?";
    try {
      c = createHash("sha256").update(readFileSync(f)).digest("hex");
    } catch {
      a.v.push(`${f} is unreadable`);
    }
    a.lines.push([`~mgr${f}`, `M ${c} ${meta(st)} ${f}`]);
  };
  for (const f of a.files) one(f);
  for (const d of a.dirs) {
    let st;
    try {
      st = lstatSync(d);
    } catch {
      a.lines.push([`~mgr${d}`, `M absent ${d}`]);
      continue;
    }
    a.lines.push([`~mgr${d}`, `M ${st.isDirectory() ? "d" : "?"} ${meta(st)} ${d}`]);
    if (!st.isDirectory()) { a.v.push(`${d} is not a directory`); continue; }
    if (st.uid !== a.uid || (st.mode & 0o022) !== 0) a.v.push(`${d} must be owned by uid ${a.uid} and not group/other writable`);
    // every entry, not just *.conf: a non-.conf entry is ignored by systemd but still recorded
    for (const n of readdirSync(d).sort()) one(path.join(d, n));
  }
}
export const EFFECTIVE_PROPS = ["FragmentPath", "DropInPaths", "Environment", "EnvironmentFiles", "ExecStart"] as const;

export function systemctlShow(unit: string): string | null {
  const r = spawnSync("systemctl", ["show", unit, ...EFFECTIVE_PROPS.flatMap((p) => ["-p", p])], { encoding: "utf8", timeout: 15_000 });
  return r.status === 0 ? r.stdout : null;
}

/** Strip runtime fields (start_time, pid, status...) from an ExecStart value. */
export function normalizeExec(v: string): { norm: string; paths: string[] } {
  const paths: string[] = [];
  const parts = [...v.matchAll(/\{([^}]*)\}/g)].map((m) => {
    const kv = m[1]!.split(" ; ").map((x) => x.trim());
    const keep = kv.filter((x) => /^(path|argv\[\]|ignore_errors|flags)=/.test(x));
    const p = keep.find((x) => x.startsWith("path="));
    if (p) paths.push(p.slice(5));
    return `{ ${keep.join(" ; ")} }`;
  });
  return { norm: parts.join(" "), paths };
}

export function parseShow(text: string): Map<string, string[]> {
  const m = new Map<string, string[]>();
  for (const line of text.split("\n")) {
    const i = line.indexOf("=");
    if (i <= 0) continue;
    const k = line.slice(0, i);
    m.set(k, [...(m.get(k) ?? []), line.slice(i + 1)]);
  }
  return m;
}

function readAttestation(file: string, uid: number): Map<string, string> {
  const out = new Map<string, string>();
  let fd: number;
  try {
    fd = openSync(file, fsc.O_RDONLY | fsc.O_NOFOLLOW);
  } catch {
    return out;
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile() || st.uid !== uid || (st.mode & 0o022) !== 0) return out;
    // R32-P3-2: the parent dir must be root-owned and not group/other writable, else the
    // file could have been replaced by whoever owns the dir.
    const pst = lstatSync(path.dirname(file));
    if (!pst.isDirectory() || pst.uid !== uid || (pst.mode & 0o022) !== 0) return out;
    for (const l of readFileSync(fd, "utf8").split("\n")) {
      const m = /^([0-9a-f]{64}) [ *](\/.+)$/.exec(l);
      if (m) out.set(m[2]!, m[1]!);
    }
  } finally {
    closeSync(fd);
  }
  return out;
}

function fileSha(file: string, attest: Map<string, string>): string | null {
  try {
    return createHash("sha256").update(readFileSync(file)).digest("hex");
  } catch {
    return attest.get(file) ?? null;
  }
}

function effectiveState(a: { units: string[]; show: (u: string) => string | null; dirs: ReadonlyArray<string>; uid: number; attest: Map<string, string>; attestPath: string; lines: Line[]; v: string[] }): void {
  const { lines, v, uid } = a;
  const meta = (st: { uid: number; gid: number; mode: number }) => `${st.uid}:${st.gid}:${(st.mode & 0o7777).toString(8)}`;
  const files = new Set<string>();
  for (const u of a.units) {
    const out = a.show(u);
    if (out === null) { v.push(`systemctl show ${u} failed`); lines.push([`~show/${u}`, `S ? ${u}`]); continue; }
    const p = parseShow(out);
    for (const k of EFFECTIVE_PROPS) {
      for (const [i, raw] of (p.get(k) ?? [""]).entries()) {
        let val = raw;
        if (k === "ExecStart") {
          const e = normalizeExec(raw);
          val = e.norm;
          e.paths.forEach((x) => files.add(x));
        } else if (k === "FragmentPath" && raw) files.add(raw);
        else if (k === "DropInPaths") raw.split(/\s+/).filter(Boolean).forEach((x) => files.add(x));
        else if (k === "EnvironmentFiles" && raw) files.add(raw.replace(/\s+\(ignore_errors=(yes|no)\)$/, ""));
        lines.push([`~show/${u}/${k}/${i}`, `S ${createHash("sha256").update(val).digest("hex")} ${u} ${k}`]);
      }
    }
  }
  const fileLine = (f: string, tag: string) => {
    let st;
    try {
      st = lstatSync(f);
    } catch {
      lines.push([`${tag}${f}`, `F absent ${f}`]);
      return;
    }
    if (st.isSymbolicLink()) {
      lines.push([`${tag}${f}`, `L ${readlinkSync(f)} ${meta(st)} ${f}`]);
      let real: string;
      try {
        real = realpathSync(f);
      } catch {
        v.push(`${f} is a dangling symlink`);
        return;
      }
      if (!files.has(real)) { files.add(real); fileLine(real, tag); }
      return;
    }
    if (!st.isFile()) { v.push(`${f} is not a regular file`); lines.push([`${tag}${f}`, `F ? ${meta(st)} ${f}`]); return; }
    if (st.uid !== uid || (st.mode & 0o022) !== 0) v.push(`${f} must be owned by uid ${uid} and not group/other writable`);
    const c = fileSha(f, a.attest);
    if (c === null) v.push(`${f} is unreadable and not in the root attestation ${a.attestPath}`);
    lines.push([`${tag}${f}`, `F ${c ?? "?"} ${meta(st)} ${f}`]);
  };
  for (const f of [...files].sort()) fileLine(f, "~file");
  // Control / runtime / generator dirs: their own owner+mode, plus every global
  // (service.d, timer.d, "mandaterail-.service.d" prefix) and mandaterail-* entry.
  const relevant = (n: string) => /^(service|timer)\.d$/.test(n) || n.startsWith("mandaterail-") || n.startsWith("mandaterail.");
  for (const d of a.dirs) {
    let st;
    try {
      st = lstatSync(d);
    } catch {
      lines.push([`~dir${d}`, `C absent ${d}`]);
      continue;
    }
    lines.push([`~dir${d}`, `C ${st.isDirectory() ? "d" : "?"} ${meta(st)} ${d}`]);
    if (!st.isDirectory()) continue;
    if (st.uid !== 0 && st.uid !== uid) v.push(`${d} must be owned by root`);
    if ((st.mode & 0o022) !== 0) v.push(`${d} must not be group/other writable`);
    for (const n of readdirSync(d).filter(relevant).sort()) {
      const e = path.join(d, n);
      const est = lstatSync(e);
      if (est.isDirectory()) {
        lines.push([`~dir${e}`, `C d ${meta(est)} ${e}`]);
        if (est.uid !== uid || (est.mode & 0o022) !== 0) v.push(`${e} must be owned by uid ${uid} and not group/other writable`);
        for (const f of readdirSync(e).sort()) fileLine(path.join(e, f), "~dir");
      } else fileLine(e, "~dir");
    }
  }
}

type Line = [string, string];
const sortHash = (lines: Line[]) => {
  lines.sort((x, y) => Buffer.compare(Buffer.from(x[0]), Buffer.from(y[0])));
  return createHash("sha256").update(lines.map((l) => l[1]).join("\n")).digest("hex");
};
const entryLine = (a: string, r: string): Line => {
  const st = lstatSync(a);
  if (st.isSymbolicLink()) return [r, `l ${readlinkSync(a)} ${r}`];
  if (st.isFile()) return [r, `f ${createHash("sha256").update(readFileSync(a)).digest("hex")} ${r}`];
  return [r, `o - ${r}`];
};

/** sha256 over sorted "<kind> <sha256|target> <relpath>" lines; node_modules and .git are skipped. */
export function releaseTreeHash(dir: string): { hash: string; files: number } {
  const lines: Line[] = [];
  const walk = (abs: string, rel: string) => {
    for (const e of readdirSync(abs, { withFileTypes: true })) {
      if (e.name === "node_modules" || e.name === ".git") continue;
      const a = path.join(abs, e.name);
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (lstatSync(a).isDirectory()) walk(a, r);
      else lines.push(entryLine(a, r));
    }
  };
  walk(dir, "");
  return { hash: sortHash(lines), files: lines.length };
}

/** R30-P3-2: files directly under a node_modules dir that are skipped (pnpm metadata). */
export const VOLATILE_DEPS_FILES = new Set([".modules.yaml", ".pnpm-workspace-state.json", ".pnpm-workspace-state-v1.json"]);
export class VolatileDepsEntryError extends Error {
  override name = "VolatileDepsEntryError";
}
export class SymlinkedNodeModulesError extends Error {
  override name = "SymlinkedNodeModulesError";
}

/**
 * R29-P3-1: sha256 over every node_modules tree in the release (root and nested
 * workspace ones), same line format, symlinks recorded by target (not followed).
 * Directories are included ("d - <rel>") so an added empty package dir changes it.
 */
export function releaseDepsHash(dir: string): { hash: string; files: number } {
  const lines: Line[] = [];
  const walkDeps = (abs: string, rel: string, top = false) => {
    for (const e of readdirSync(abs, { withFileTypes: true })) {
      // R30-P3-2: pnpm's install metadata (timestamps, store path) is not code and differs
      // between two clean installs of the same lockfile, so it is not hashed.
      const a = path.join(abs, e.name);
      // R31-P3-2: only a REGULAR file of that name is skipped; a directory, symlink or
      // anything else under a volatile name is refused (it could hide code).
      if (top && VOLATILE_DEPS_FILES.has(e.name)) {
        if (lstatSync(a).isFile()) continue;
        throw new VolatileDepsEntryError(`release-pin: ${rel}/${e.name} is not a regular file (refused; volatile pnpm metadata names are skipped only as regular files)`);
      }
      const r = `${rel}/${e.name}`;
      if (lstatSync(a).isDirectory()) {
        lines.push([r, `d - ${r}`]);
        walkDeps(a, r);
      } else lines.push(entryLine(a, r));
    }
  };
  const find = (abs: string, rel: string) => {
    for (const e of readdirSync(abs, { withFileTypes: true })) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      // R30-P3-2: a symlinked node_modules would point the hash (and the code) elsewhere.
      if (e.name === "node_modules" && e.isSymbolicLink()) throw new SymlinkedNodeModulesError(`release-pin: ${r} is a symlink (refused; node_modules must be a real directory in the release)`);
      if (e.name === ".git" || !e.isDirectory()) continue;
      const a = path.join(abs, e.name);
      if (e.name === "node_modules") {
        lines.push([r, `d - ${r}`]);
        walkDeps(a, r, true);
      } else find(a, r);
    }
  };
  find(dir, "");
  return { hash: sortHash(lines), files: lines.length };
}

/**
 * R29-P3-1: paths (relative) in the release, node_modules included, that are not owned
 * by `uid` or are group/other writable (symlinks: owner only), plus ancestors of the
 * release that are not owned by root/`uid` or are group/other writable without the
 * sticky bit. Returns at most `max` examples and the total count.
 */
export function releaseOwnershipViolations(dir: string, uid = 0, max = 5): { count: number; examples: string[] } {
  const examples: string[] = [];
  let count = 0;
  const bad = (p: string) => {
    count++;
    if (examples.length < max) examples.push(p);
  };
  const check = (a: string, r: string) => {
    const st = lstatSync(a);
    if (st.uid !== uid || (!st.isSymbolicLink() && (st.mode & 0o022) !== 0)) bad(r);
    if (st.isDirectory()) for (const e of readdirSync(a)) check(path.join(a, e), `${r}/${e}`);
  };
  check(dir, ".");
  for (let p = path.dirname(dir); ; p = path.dirname(p)) {
    const st = statSync(p);
    if ((st.uid !== 0 && st.uid !== uid) || ((st.mode & 0o022) !== 0 && (st.mode & 0o1000) === 0)) bad(p);
    if (p === path.dirname(p)) break;
  }
  return { count, examples };
}

export function formatReleasePin(p: ReleasePin): string {
  return `commit=${p.commit}\ntree_sha256=${p.treeSha256}\ndeps_sha256=${p.depsSha256}\nmanifest_sha256=${p.manifestSha256}\nsystemd_sha256=${p.systemdSha256}\n`;
}

export function parseReleasePin(text: string): ReleasePin | null {
  const kv: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const m = /^([a-z0-9_]+)=(.*)$/.exec(line.trim());
    if (m) kv[m[1]!] = m[2]!.trim();
  }
  const commit = kv.commit ?? "", treeSha256 = kv.tree_sha256 ?? "", depsSha256 = kv.deps_sha256 ?? "", manifestSha256 = kv.manifest_sha256 ?? "", systemdSha256 = kv.systemd_sha256 ?? "";
  const h64 = /^[0-9a-f]{64}$/;
  if (!/^[0-9a-f]{40}$/.test(commit) || !h64.test(treeSha256) || !h64.test(depsSha256) || !h64.test(manifestSha256) || !h64.test(systemdSha256)) return null;
  return { commit, treeSha256, depsSha256, manifestSha256, systemdSha256 };
}

/** R29 optional: read the pin with O_NOFOLLOW and check owner / mode on the open fd. */
function readPinNoFollow(file: string, uid: number): { text: string } | { reason: string } {
  let fd: number;
  try {
    fd = openSync(file, fsc.O_RDONLY | fsc.O_NOFOLLOW);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === "ELOOP" || code === "EMLINK") return { reason: `release pin: ${file} is a symlink (refused, O_NOFOLLOW)` };
    return { reason: `release pin: ${file} is missing or unreadable (the deploy writes it)` };
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) return { reason: `release pin: ${file} is not a regular file` };
    if (st.uid !== uid || (st.mode & 0o022) !== 0) return { reason: `release pin: ${file} must be owned by uid ${uid} and not group/other writable` };
    return { text: readFileSync(fd, "utf8") };
  } catch {
    return { reason: `release pin: ${file} is missing or unreadable (the deploy writes it)` };
  } finally {
    closeSync(fd);
  }
}

/** Alert reasons (empty = fine) for the release pin. */
export function releasePinReasons(a: {
  env: Record<string, string | undefined>;
  root: string;
  manifestPath: string;
  pinnedSha256: string;
  /** default DEFAULT_RELEASE_PIN_PATH; MONITOR_RELEASE_PIN only off mainnet / production */
  pinPath?: string;
  /** owner uid the pin file and the release tree must have (default 0 = root) */
  ownerUid?: number;
  /** R30-P3-3: where the units / env files live (tests only) */
  systemd?: Omit<SystemdOpts, "uid">;
}): { reasons: string[]; commit: string | null } {
  const override = a.env.MONITOR_RELEASE_PIN?.trim();
  const prod = (a.env.NETWORK ?? "").trim().toLowerCase() === "mainnet" || (a.env.NODE_ENV ?? "").trim().toLowerCase() === "production";
  if (override && prod) return { reasons: ["release pin: MONITOR_RELEASE_PIN is refused on mainnet / NODE_ENV=production"], commit: null };
  const file = a.pinPath ?? (override || DEFAULT_RELEASE_PIN_PATH);
  const uid = a.ownerUid ?? 0;
  const read = readPinNoFollow(file, uid);
  if ("reason" in read) return { reasons: [read.reason], commit: null };
  const pin = parseReleasePin(read.text);
  if (!pin) return { reasons: ["release pin: malformed (needs commit=<40 hex>, tree_sha256, deps_sha256, manifest_sha256, systemd_sha256=<64 hex>)"], commit: null };
  const out: string[] = [];
  let root = a.root;
  try {
    root = realpathSync(a.root);
  } catch {
    /* keep */
  }
  const base = path.basename(root);
  if (!/^[0-9a-f]{7,40}$/.test(base) || !pin.commit.startsWith(base)) out.push(`release pin: running release ${base} is not the pinned commit ${pin.commit.slice(0, 12)}`);
  if (pin.manifestSha256 !== a.pinnedSha256) out.push(`release pin: manifest sha256 ${pin.manifestSha256.slice(0, 16)}… in the pin differs from the code pin ${a.pinnedSha256.slice(0, 16)}…`);
  let actual = "missing";
  try {
    actual = createHash("sha256").update(readFileSync(a.manifestPath)).digest("hex");
  } catch {
    /* reported below */
  }
  if (actual !== pin.manifestSha256) out.push(`release pin: deployed manifest sha256 ${actual.slice(0, 16)}… differs from the pin ${pin.manifestSha256.slice(0, 16)}…`);
  const t = releaseTreeHash(root);
  if (t.hash !== pin.treeSha256) out.push(`release pin: release tree hash ${t.hash.slice(0, 16)}… (${t.files} files) differs from the pin ${pin.treeSha256.slice(0, 16)}… (code changed after deploy)`);
  let d: { hash: string; files: number };
  try {
    d = releaseDepsHash(root);
  } catch (e) {
    out.push(String((e as Error).message));
    d = { hash: "refused", files: 0 };
  }
  if (d.hash !== "refused" && d.hash !== pin.depsSha256) out.push(`release pin: installed dependencies hash ${d.hash.slice(0, 16)}… (${d.files} entries) differs from the pin ${pin.depsSha256.slice(0, 16)}… (node_modules changed after deploy)`);
  const sd = systemdState({ ...a.systemd, uid });
  for (const x of sd.violations) out.push(`release pin: systemd/env (R30-P3-3): ${x}`);
  if (sd.hash !== pin.systemdSha256) out.push(`release pin: systemd units / drop-ins / env-file modes hash ${sd.hash.slice(0, 16)}… (${sd.entries} entries) differs from the pin ${pin.systemdSha256.slice(0, 16)}… (changed after deploy)`);
  const own = releaseOwnershipViolations(root, uid);
  if (own.count > 0) out.push(`release pin: ${own.count} release path(s) not owned by uid ${uid} or group/other writable (R29-P3-1), e.g. ${own.examples.join(", ")}`);
  return { reasons: out, commit: pin.commit };
}

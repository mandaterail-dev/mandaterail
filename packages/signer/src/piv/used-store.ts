/**
 * used.db (§6.2b): spendKey -> used, single-use forever for this key. Append-only journal with fsync per entry
 * (Node 20 has no built-in SQLite; the journal is the authoritative file, chattr +a on the host).
 * Fail-closed: a missing journal refuses to start unless rebuilt from the log copy/snapshot AND the DB list,
 * and the rebuilt set must be a superset of the DB list (R42-P3-1 export procedure in cli/export-used.ts).
 */
import { closeSync, constants, existsSync, fsyncSync, openSync, readFileSync, writeSync } from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";

export class UsedStoreError extends Error {}
const lineOf = (e: { spendKey: string; msgHash: string; at: number }) => {
  const j = JSON.stringify(e);
  return `${j}\t${createHash("sha256").update(j).digest("hex").slice(0, 16)}\n`;
};
function parse(text: string): Map<string, string> {
  const m = new Map<string, string>();
  for (const l of text.split("\n")) {
    if (!l) continue;
    const [j, h] = l.split("\t");
    if (!j || createHash("sha256").update(j).digest("hex").slice(0, 16) !== h) throw new UsedStoreError("used journal corrupt");
    const e = JSON.parse(j) as { spendKey: string; msgHash: string };
    m.set(e.spendKey, e.msgHash);
  }
  return m;
}

export class UsedStore {
  private readonly used: Map<string, string>;
  private constructor(private readonly file: string, used: Map<string, string>) { this.used = used; }

  static open(file: string): UsedStore {
    if (!existsSync(file)) throw new UsedStoreError("used journal missing: refusing to start (rebuild required)");
    return new UsedStore(file, parse(readFileSync(file, "utf8")));
  }
  static init(file: string): UsedStore {
    const fd = openSync(file, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    try { fsyncSync(fd); } finally { closeSync(fd); }
    const d = openSync(path.dirname(file), constants.O_RDONLY); // R43-P3: the new entry is durable too
    try { fsyncSync(d); } finally { closeSync(d); }
    return new UsedStore(file, new Map());
  }
  /** Rebuild from surviving copies (log copy, snapshot) and the DB's attested list; must cover the DB list. */
  static rebuild(file: string, copies: string[], dbSpendKeys: string[]): UsedStore {
    if (existsSync(file)) throw new UsedStoreError("journal exists; rebuild only replaces a missing one");
    const m = new Map<string, string>();
    for (const c of copies) for (const [k, v] of parse(c)) m.set(k, v);
    for (const k of dbSpendKeys) if (!m.has(k)) m.set(k, "db-export");
    const s = UsedStore.init(file);
    for (const [k, v] of m) s.append(k, v);
    for (const k of dbSpendKeys) if (!s.has(k)) throw new UsedStoreError("rebuilt set is not a superset of the DB list");
    return s;
  }
  has(spendKey: string): boolean { return this.used.has(spendKey); }
  /** Marks used BEFORE the PIV sign (a crash after this burns the spend, never double-signs). */
  markUsed(spendKey: string, msgHash: string): void {
    if (this.used.has(spendKey)) throw new UsedStoreError("spend already signed");
    this.append(spendKey, msgHash);
  }
  private append(spendKey: string, msgHash: string): void {
    const fd = openSync(this.file, constants.O_WRONLY | constants.O_APPEND | constants.O_NOFOLLOW);
    try { writeSync(fd, lineOf({ spendKey, msgHash, at: Date.now() })); fsyncSync(fd); } finally { closeSync(fd); }
    this.used.set(spendKey, msgHash);
  }
}

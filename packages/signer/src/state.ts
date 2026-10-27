/**
 * Durable, fail-closed local state: a file written via temp + fsync + rename, plus a monotonic counter that
 * must never go backwards. A missing state file refuses (it is created only by an explicit init).
 */
import { closeSync, fsyncSync, openSync, readFileSync, renameSync, writeSync, existsSync, constants } from "node:fs";
import path from "node:path";

export class StateError extends Error {}

export class DurableJson<T extends { counter: number }> {
  private cur: T;
  constructor(private readonly file: string) {
    if (!existsSync(file)) throw new StateError(`${path.basename(file)} missing: refusing to start (run init)`);
    this.cur = JSON.parse(readFileSync(file, "utf8")) as T;
    if (!Number.isSafeInteger(this.cur.counter) || this.cur.counter < 0) throw new StateError("state counter corrupt");
  }
  static init<T extends { counter: number }>(file: string, v: T): void {
    const fd = openSync(file, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    try { writeSync(fd, JSON.stringify(v)); fsyncSync(fd); } finally { closeSync(fd); }
  }
  get(): T {
    return structuredClone(this.cur);
  }
  /** Writes the next state; the counter must strictly increase (monotonic). */
  put(next: T): void {
    if (next.counter <= this.cur.counter) throw new StateError("monotonic counter would not increase");
    const tmp = `${this.file}.tmp`;
    const fd = openSync(tmp, constants.O_CREAT | constants.O_TRUNC | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    try { writeSync(fd, JSON.stringify(next)); fsyncSync(fd); } finally { closeSync(fd); }
    renameSync(tmp, this.file);
    const d = openSync(path.dirname(this.file), constants.O_RDONLY);
    try { fsyncSync(d); } finally { closeSync(d); }
    this.cur = structuredClone(next);
  }
}

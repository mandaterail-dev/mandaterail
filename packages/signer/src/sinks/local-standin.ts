/**
 * TESTNET-ONLY STAND-IN for the off-host B2 Object Lock sink. It is NOT off-host and NOT immutable against
 * root: it is an O_APPEND file on the box, used only for the TestNet rehearsal while no B2 account exists in
 * the owner's name. Same AuditSink interface; constructing it requires the explicit label and network=testnet.
 * It also refuses to rewrite history it can see: appends only, and last() verifies the file wasn't truncated
 * below the highest seq this process has written.
 */
import { closeSync, existsSync, fsyncSync, openSync, readFileSync, writeSync } from "node:fs";
import type { AuditSink } from "../audit.js";

export { STANDIN_LABEL } from "./labels.js";
import { STANDIN_LABEL } from "./labels.js";

export class LocalAppendStandInSink implements AuditSink {
  private maxSeen = 0;
  constructor(private readonly file: string, opts: { network: string; label: string }) {
    if (opts.network !== "testnet" || opts.label !== STANDIN_LABEL) throw new Error("LocalAppendStandInSink is TESTNET-ONLY and must be explicitly labeled");
  }
  async append(line: string): Promise<void> {
    if (line.includes("\n")) throw new Error("line contains a newline");
    const fd = openSync(this.file, "a", 0o640);
    try { writeSync(fd, line + "\n"); fsyncSync(fd); } finally { closeSync(fd); }
    const seq = (JSON.parse(line.split("\t")[0]!) as { seq?: number }).seq ?? 0;
    this.maxSeen = Math.max(this.maxSeen, seq);
  }
  async at(seq: number): Promise<string | null> {
    if (!existsSync(this.file)) return null;
    return readFileSync(this.file, "utf8").split("\n").filter(Boolean).find((l) => (JSON.parse(l.split("\t")[0]!) as { seq?: number }).seq === seq) ?? null;
  }
  async last(): Promise<string | null> {
    if (!existsSync(this.file)) return null;
    const lines = readFileSync(this.file, "utf8").split("\n").filter(Boolean);
    const l = lines.at(-1) ?? null;
    const seq = l ? ((JSON.parse(l.split("\t")[0]!) as { seq?: number }).seq ?? 0) : 0;
    if (seq < this.maxSeen) throw new Error("stand-in log was truncated");
    return l;
  }
}

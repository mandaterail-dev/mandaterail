/**
 * Off-host, append-only, hash-chained event log (rev 10 §13 "Monitoring").
 * - R43-P3: the chain head is loaded from the sink at start, not reset to zeros.
 * - R43-P2-1: every event carries the local state counters; at boot the signer refuses unless its counters are
 *   >= the last ones recorded off-host (a rolled-back or wiped policy/nonce state is detected).
 * - R43-P2-2: a failed page on an alert event throws PageFailed (the signer pauses); the heartbeat refuses
 *   unless the last page was delivered and a test publish succeeds.
 * Events never carry secrets: no PINs, keys or request signatures.
 */
import { createHash } from "node:crypto";

/** helper = mr-piv-sign's own state counter as last reported in a sign reply (R44-P3-1 off-host anchoring) */
export interface Counters { policy: number; requests: number; helper?: number }
export interface AuditEvent { seq?: number; kind: string; spendKey?: string; reason?: string; msgHash?: string; at: number; counters?: Counters }
export interface AuditSink {
  append(line: string): Promise<void>;
  /** last line appended (from the off-host store), or null when the log is empty */
  last(): Promise<string | null>;
  /** R45-P3-1: the line with this seq, or null (used at open to check that the head links to seq - 1) */
  at(seq: number): Promise<string | null>;
}
export type Pager = (subject: string, body: string) => Promise<void>;
export class AuditUnavailable extends Error {}
export class PageFailed extends Error {}
export class RollbackDetected extends Error {}

const hashOf = (line: string) => createHash("sha256").update(line).digest("hex");

export class ChainedAudit {
  private lastPageOk = true;
  private constructor(private readonly sink: AuditSink, private readonly page: Pager, private prev: string, readonly lastCounters: Counters | null, private seq: number) {}

  /**
   * Opens the chain at the sink's head (verifying the head line's own hash).
   * R44-P3-1: `minSeq` is the operator's pinned lower bound for the head sequence (recorded at install / after
   * each review). An empty bucket, or a head below the pin (a wiped or swapped bucket), refuses to open.
   */
  static async open(sink: AuditSink, page: Pager, opts: { minSeq?: number } = {}): Promise<ChainedAudit> {
    const minSeq = opts.minSeq ?? 0;
    let last: string | null;
    try { last = await sink.last(); } catch (e) { throw new AuditUnavailable(`audit sink unavailable: ${(e as Error).message}`); }
    if (!last) {
      if (minSeq > 0) throw new RollbackDetected(`audit log is empty but the pinned minimum sequence is ${minSeq}: wiped or swapped`);
      return new ChainedAudit(sink, page, "0".repeat(64), null, 0);
    }
    const [line, h] = last.split("\t");
    if (!line || !h || hashOf(line) !== h) throw new AuditUnavailable("audit head line is corrupt");
    const ev = JSON.parse(line) as AuditEvent;
    const seq = typeof ev.seq === "number" ? ev.seq : 0;
    if (seq < minSeq) throw new RollbackDetected(`audit head sequence ${seq} is below the pinned minimum ${minSeq}: rolled back or swapped`);
    // R45-P3-1: the head must link to the event before it (a forged higher-seq head with a made-up prev is refused)
    if (seq > 1) {
      let p: string | null;
      try { p = await sink.at(seq - 1); } catch (e) { throw new AuditUnavailable(`audit sink unavailable: ${(e as Error).message}`); }
      const [pl, ph] = (p ?? "").split("\t");
      const pev = pl ? (JSON.parse(pl) as AuditEvent & { prev?: string }) : null;
      if (!pl || !ph || hashOf(pl) !== ph || pev?.seq !== seq - 1 || (ev as AuditEvent & { prev?: string }).prev !== ph) {
        throw new AuditUnavailable(`audit head (seq ${seq}) does not link to seq ${seq - 1}: forged or corrupt head`);
      }
    }
    return new ChainedAudit(sink, page, h, ev.counters ?? null, seq);
  }

  headSeq(): number { return this.seq; }

  /**
   * rev 21 resume check: re-read the off-host head and require it to be exactly the line this signer wrote last
   * (same seq and hash, valid line hash, links to seq - 1). A fork, a second writer or a rolled-back bucket refuses.
   */
  async checkHead(): Promise<{ seq: number; head: string }> {
    await this.tail;
    if (this.ambiguous) throw new AuditUnavailable("an append is still ambiguous");
    let last: string | null;
    try { last = await this.sink.last(); } catch (e) { throw new AuditUnavailable(`audit sink unavailable: ${(e as Error).message}`); }
    const [line, h] = (last ?? "").split("\t");
    if (!line || !h || hashOf(line) !== h) throw new RollbackDetected("audit head unreadable or corrupt");
    const ev = JSON.parse(line) as AuditEvent & { prev?: string };
    if (ev.seq !== this.seq || h !== this.prev) throw new RollbackDetected(`off-host head (seq ${String(ev.seq)}) is not the line this signer wrote last (seq ${this.seq})`);
    if (this.seq > 1) {
      const p = await this.sink.at(this.seq - 1);
      const [pl, ph] = (p ?? "").split("\t");
      if (!pl || !ph || hashOf(pl) !== ph || ev.prev !== ph) throw new RollbackDetected(`off-host head does not link to seq ${this.seq - 1}`);
    }
    return { seq: this.seq, head: h };
  }

  /** R44-P3-1: the helper's counter must strictly increase across sign replies (rolled-back helper.json). */
  assertHelperAdvanced(reported: number): void {
    const prev = this.lastHelper ?? this.lastCounters?.helper;
    if (prev !== undefined && !(reported > prev)) {
      throw new RollbackDetected(`helper counter ${reported} did not advance past the off-host record ${prev}: helper state rolled back`);
    }
    this.lastHelper = reported;
  }
  private lastHelper: number | undefined;
  helperCounter(): number | undefined { return this.lastHelper ?? this.lastCounters?.helper; }

  /** R43-P2-1: refuse to start when local counters are behind the off-host record. */
  assertNotRolledBack(local: Counters): void {
    const c = this.lastCounters;
    if (!c) return;
    if (local.policy < c.policy || local.requests < c.requests) {
      throw new RollbackDetected(`local state counters (policy ${local.policy}, requests ${local.requests}) are behind the off-host log (policy ${c.policy}, requests ${c.requests}): rolled back or wiped`);
    }
  }

  pageHealthy(): boolean { return this.lastPageOk; }

  /**
   * R46-P2-1: serialize the APPEND so concurrent requests never share a seq/prev (promise-chain mutex).
   * R47-P3: the page runs AFTER the lock is released, so a slow ntfy can't hold every other request for 10 s.
   */
  private tail: Promise<unknown> = Promise.resolve();
  async log(e: AuditEvent, alert = false): Promise<void> {
    const run = this.tail.then(() => this.appendLocked(e));
    this.tail = run.catch(() => undefined);
    await run;
    if (alert) {
      try {
        await this.page(`[signer] ${e.kind}`, `${e.spendKey ?? ""} ${e.reason ?? ""}`.trim());
        this.lastPageOk = true;
      } catch (err) {
        this.lastPageOk = false;
        throw new PageFailed(`page failed for ${e.kind}: ${(err as Error).message}`);
      }
    }
  }

  /** R47-P3: an append whose outcome is unknown (stored, but the ack was lost / timed out) */
  private ambiguous: { seq: number; stored: string; h: string } | null = null;

  private async appendLocked(e: AuditEvent): Promise<void> {
    // R47-P3: resolve an earlier ambiguous append first: if it landed, adopt it (seq advances); if the slot is
    // empty, reuse the seq; anything else at that seq is a fork -> refuse (fail closed).
    if (this.ambiguous) {
      const a = this.ambiguous;
      let got: string | null;
      try { got = await this.sink.at(a.seq); } catch (err) { throw new AuditUnavailable(`audit sink unavailable: ${(err as Error).message}`); }
      if (got === a.stored) { this.prev = a.h; this.seq = a.seq; }
      else if (got !== null) throw new AuditUnavailable(`audit seq ${a.seq} holds a line this signer did not write: fork / second writer`);
      this.ambiguous = null;
    }
    const seq = this.seq + 1;
    const line = JSON.stringify({ seq, ...e, prev: this.prev });
    const h = hashOf(line);
    const stored = `${line}\t${h}`;
    try {
      await this.sink.append(stored);
    } catch (err) {
      this.ambiguous = { seq, stored, h };
      throw new AuditUnavailable(`audit sink unavailable: ${(err as Error).message}`);
    }
    this.prev = h;
    this.seq = seq;
  }

  /** Heartbeat test publish: the SAME topic as the alerts, sent at priority "min" (pager.ts). */
  async testPage(): Promise<void> {
    try {
      await this.page("[signer] heartbeat test", "");
      this.lastPageOk = true;
    } catch (err) {
      this.lastPageOk = false;
      throw new PageFailed(`test page failed: ${(err as Error).message}`);
    }
  }
}

/** Heartbeat canary: pings the dead-man URL only when the self-checks (incl. the page path) pass. */
export async function heartbeat(selfCheck: () => Promise<void>, ping: () => Promise<void>): Promise<boolean> {
  try {
    await selfCheck();
  } catch {
    return false; // no ping: the dead-man switch fires
  }
  await ping();
  return true;
}

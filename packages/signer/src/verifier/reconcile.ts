/**
 * R49-P2-1 / R49-P2-2: the verifier (outside Google) cross-checks Google's own record of key use against the
 * signer's off-host chain, and watches the GCP alert forwarder's daily heartbeat.
 *
 * Reconcile: every Cloud KMS `AsymmetricSign` audit entry for the pinned key version must match one `signed`
 * event in the off-host chain (within ±skew), and every `signed` event must match one AsymmetricSign. Entries
 * must also come from the pinned SA, the reserved static internal IP and the pinned VPC network. Any mismatch,
 * gap, chain-link break or source error pages. The cursor only moves forward after a clean window.
 *
 * Heartbeat dead-man: the forwarder publishes a heartbeat daily (Cloud Scheduler → Pub/Sub → forwarder → ntfy,
 * and a Healthchecks ping). The verifier polls the forwarder's ntfy topic and pages if the newest heartbeat is
 * older than maxAge (default 26 h). Healthchecks pages independently if its ping stops.
 */
import { createHash } from "node:crypto";
import type { RequestAuth, SignedRequest } from "../requests.js";
import type { AuditSink } from "../audit.js";
import type { DurableJson } from "../state.js";

type Fetch = typeof fetch;
export interface KmsSignEntry { insertId: string; at: number; principal: string; callerIp: string; callerNetwork: string; keyVersion: string }
export interface KmsAuditSource { list(fromMs: number, toMs: number): Promise<KmsSignEntry[]> }
export interface ChainSigned { seq: number; at: number }
export interface ReconcileState { counter: number; cursorMs: number; seq: number; headHash: string; hbSeenMs: number; hbPaged: boolean; pending: ChainSigned[];
  /** R50-P3: the open (unacknowledged) mismatch for the current window, if any */
  open?: { windowFrom: number; windowTo: number; hash: string; problems: string[] } | null;
  acks?: { at: number; hash: string; reason: string; by: string }[] }
export const initialReconcileState = (startMs: number): ReconcileState => ({ counter: 0, cursorMs: startMs, seq: 0, headHash: "0".repeat(64), hbSeenMs: startMs, hbPaged: false, pending: [] });

export interface ReconcilePins { keyVersion: string; signerSa: string; signerIp: string; signerNetwork: string; skewMs?: number; lagMs?: number }

/** Cloud Logging entries:list for AsymmetricSign on the pinned key version. `token` yields a read-only (roles/logging.privateLogViewer) access token. */
export function gcpLoggingSource(o: { project: string; keyVersion: string; token: () => Promise<string>; fetch?: Fetch }): KmsAuditSource {
  const f = o.fetch ?? fetch;
  return {
    async list(fromMs, toMs) {
      const out: KmsSignEntry[] = [];
      let pageToken: string | undefined;
      const filter = `protoPayload.serviceName="cloudkms.googleapis.com" AND protoPayload.methodName="AsymmetricSign" AND protoPayload.resourceName="${o.keyVersion}" AND timestamp>="${new Date(fromMs).toISOString()}" AND timestamp<"${new Date(toMs).toISOString()}"`;
      for (let i = 0; i < 50; i++) {
        const r = await f("https://logging.googleapis.com/v2/entries:list", {
          method: "POST", redirect: "error", signal: AbortSignal.timeout(20_000),
          headers: { authorization: `Bearer ${await o.token()}`, "content-type": "application/json" },
          body: JSON.stringify({ resourceNames: [`projects/${o.project}`], filter, orderBy: "timestamp asc", pageSize: 1000, pageToken }),
        } as RequestInit);
        if (r.status !== 200) throw new Error(`logging entries:list status ${r.status}`);
        const j = (await r.json()) as { entries?: Record<string, any>[]; nextPageToken?: string };
        for (const e of j.entries ?? []) {
          const p = e.protoPayload ?? {};
          out.push({ insertId: String(e.insertId), at: Date.parse(String(e.timestamp)), principal: String(p.authenticationInfo?.principalEmail ?? ""),
            callerIp: String(p.requestMetadata?.callerIp ?? ""), callerNetwork: String(p.requestMetadata?.callerNetwork ?? ""), keyVersion: String(p.resourceName ?? "") });
        }
        if (!j.nextPageToken) return out;
        pageToken = j.nextPageToken;
      }
      throw new Error("logging entries:list: too many pages");
    },
  };
}

/**
 * R51-P3: the ack hash covers the window START and the full problem list only. The window END moves forward on
 * every tick (now - lag), so including it made an ack computed from status() go stale before it could be sent.
 * A new or different problem still changes the hash, so nothing can be acked blind.
 */
export const problemsHash = (from: number, p: string[]) => createHash("sha256").update(JSON.stringify([from, p])).digest("hex");
const hashOf = (l: string) => createHash("sha256").update(l).digest("hex");

export class Reconciler {
  constructor(private readonly pins: ReconcilePins, private readonly d: {
    kms: KmsAuditSource; chain: AuditSink; st: DurableJson<ReconcileState>; page: (s: string, b: string) => Promise<void>; now?: () => number;
  }) {}

  /** Reads new chain lines, verifying the hash links; returns the `signed` events. */
  private async readChain(st: ReconcileState): Promise<{ signed: ChainSigned[]; seq: number; headHash: string }> {
    const signed: ChainSigned[] = [];
    let seq = st.seq, head = st.headHash;
    for (let i = 0; i < 100_000; i++) {
      const raw = await this.d.chain.at(seq + 1);
      if (raw === null) break;
      const [line, h] = raw.split("\t");
      const ev = JSON.parse(line ?? "{}") as { seq?: number; prev?: string; kind?: string; at?: number };
      if (!line || hashOf(line) !== h || ev.seq !== seq + 1 || ev.prev !== head) throw new Error(`chain link broken at seq ${seq + 1}`);
      if (ev.kind === "signed") signed.push({ seq: ev.seq, at: Number(ev.at) });
      seq = ev.seq; head = h!;
    }
    return { signed, seq, headHash: head };
  }

  /**
   * R50-P3: acknowledge the open mismatch after investigating it. Requester-signed (op "reconcile-ack", same
   * request keys and nonces as the CLI), must name the exact problem-set hash (so a new, different mismatch can't be
   * acked blind), needs a reason, is paged, and is kept in state. The cursor then moves past that window only.
   */
  async acknowledge(req: SignedRequest, auth: RequestAuth): Promise<{ acked: string; cursorMs: number }> {
    const b = auth.verify(req, "reconcile-ack");
    const st = this.d.st.get();
    if (!st.open) throw new Error("nothing to acknowledge");
    if (b.hash !== st.open.hash) throw new Error("ack names another problem set (re-read status)");
    const reason = String(b.reason ?? "").trim();
    if (reason.length < 10) throw new Error("ack needs a reason (>= 10 chars)");
    const by = String(b.requester);
    await this.d.page("[verifier] KMS/chain mismatch ACKNOWLEDGED", `${st.open.hash.slice(0, 16)} ${reason.slice(0, 300)}`);
    const skew = this.pins.skewMs ?? 120_000;
    this.d.st.put({ ...st, counter: st.counter + 1, cursorMs: st.open.windowTo, open: null,
      pending: st.pending.filter((x) => x.at >= st.open!.windowTo - skew),
      acks: [...(st.acks ?? []), { at: (this.d.now ?? Date.now)(), hash: st.open.hash, reason: reason.slice(0, 300), by }].slice(-500) });
    return { acked: st.open.hash, cursorMs: st.open.windowTo };
  }

  /** Read-only: the open mismatch (to build an ack). */
  status(): { open: ReconcileState["open"]; problemCount: number; cursorMs: number } {
    const s = this.d.st.get();
    return { open: s.open ?? null, problemCount: s.open?.problems.length ?? 0, cursorMs: s.cursorMs };
  }

  /** One pass. Returns the mismatches it paged (empty = clean). Also keeps signed events seen ahead of the window. */
  async tick(): Promise<string[]> {
    const now = (this.d.now ?? Date.now)();
    const skew = this.pins.skewMs ?? 120_000, lag = this.pins.lagMs ?? 600_000;
    const st = this.d.st.get();
    const until = now - lag;
    if (until <= st.cursorMs) return [];
    const problems: string[] = [];
    let kms: KmsSignEntry[], chain;
    try {
      kms = await this.d.kms.list(st.cursorMs - skew, until + skew);
      chain = await this.readChain(st);
    } catch (e) {
      const m = `reconcile source error: ${(e as Error).message}`;
      await this.d.page("[verifier] KMS reconcile ERROR", m);
      return [m];
    }
    const pending = [...(st.pending ?? []), ...chain.signed];
    const inWin = (t: number) => t >= st.cursorMs && t < until;
    for (const e of kms.filter((x) => inWin(x.at))) {
      if (e.keyVersion !== this.pins.keyVersion) problems.push(`sign on unexpected key version ${e.keyVersion}`);
      if (e.principal !== this.pins.signerSa) problems.push(`sign by ${e.principal || "?"} (not the signer SA) at ${new Date(e.at).toISOString()}`);
      if (e.callerIp !== this.pins.signerIp || e.callerNetwork !== this.pins.signerNetwork) problems.push(`sign from ${e.callerIp || "?"} / ${e.callerNetwork || "?"} (not the signer VM's reserved IP + VPC) at ${new Date(e.at).toISOString()}`);
    }
    // 1:1 matching by time: KMS entries (in window) ↔ chain `signed` (any time within skew)
    const used = new Set<number>(), usedK = new Set<string>();
    const ks = [...kms].sort((a, b) => a.at - b.at);
    for (const k of ks) {
      const c = pending.find((s) => !used.has(s.seq) && Math.abs(s.at - k.at) <= skew);
      if (c) { used.add(c.seq); usedK.add(k.insertId); }
    }
    for (const k of ks) if (inWin(k.at) && !usedK.has(k.insertId)) problems.push(`AsymmetricSign ${k.insertId} at ${new Date(k.at).toISOString()} has no 'signed' chain event`);
    for (const s of pending) if (inWin(s.at) && !used.has(s.seq)) problems.push(`chain 'signed' seq ${s.seq} has no AsymmetricSign audit entry`);
    if (problems.length) {
      await this.d.page("[verifier] ANOMALY KMS/chain mismatch", problems.slice(0, 20).join("\n"));
      // the cursor stays: the window is re-checked (and re-paged) until acknowledged (acknowledge())
      // R51-P3: keep (and hash) every problem, not just the first 50, so status() shows all of them
      const hash = problemsHash(st.cursorMs, problems);
      this.d.st.put({ ...st, counter: st.counter + 1, seq: chain.seq, headHash: chain.headHash, pending: pending.slice(-10_000), open: { windowFrom: st.cursorMs, windowTo: until, hash, problems } });
      return problems;
    }
    this.d.st.put({ ...st, open: null, counter: st.counter + 1, cursorMs: until, seq: chain.seq, headHash: chain.headHash, pending: pending.filter((x) => x.at >= until - skew).slice(-10_000) });
    return [];
  }
}

/** Newest heartbeat time on the forwarder's ntfy topic (ntfy JSON poll API), or null. The topic is a capability: never logged. */
export function ntfyHeartbeatSource(o: { server?: string; topic: string; since?: string; fetch?: Fetch }): () => Promise<number | null> {
  const f = o.fetch ?? fetch;
  const base = (o.server ?? "https://ntfy.sh").replace(/\/$/, "");
  return async () => {
    let r: Response;
    try { r = await f(`${base}/${o.topic}/json?poll=1&since=${o.since ?? "48h"}`, { redirect: "error", signal: AbortSignal.timeout(15_000) } as RequestInit); }
    catch (e) { throw new Error(`ntfy poll failed: ${(e as Error).message.replace(o.topic, "<topic>")}`); }
    if (r.status !== 200) throw new Error(`ntfy poll status ${r.status}`);
    let best: number | null = null;
    for (const l of (await r.text()).split("\n")) {
      if (!l.trim()) continue;
      const m = JSON.parse(l) as { event?: string; time?: number; tags?: string[] };
      if (m.event === "message" && (m.tags ?? []).includes("heartbeat") && typeof m.time === "number") best = Math.max(best ?? 0, m.time * 1000);
    }
    return best;
  };
}

/** Dead-man for the forwarder heartbeat: pages once when it goes stale (or can't be read), and once when it recovers. */
export async function checkForwarderHeartbeat(d: { latest: () => Promise<number | null>; st: DurableJson<ReconcileState>; page: (s: string, b: string) => Promise<void>; maxAgeMs?: number; now?: () => number }): Promise<boolean> {
  const now = (d.now ?? Date.now)(), max = d.maxAgeMs ?? 26 * 3_600_000;
  const st = d.st.get();
  let latest: number | null = null, err = "";
  try { latest = await d.latest(); } catch (e) { err = (e as Error).message; }
  const seen = Math.max(st.hbSeenMs, latest ?? 0);
  const ok = !err && now - seen <= max;
  if (!ok && !st.hbPaged) await d.page("[verifier] ANOMALY GCP alert forwarder heartbeat stopped", err || `last heartbeat ${new Date(seen).toISOString()}: GCP alerts may be silenced`);
  if (ok && st.hbPaged) await d.page("[verifier] GCP alert forwarder heartbeat back", new Date(seen).toISOString());
  d.st.put({ ...st, counter: st.counter + 1, hbSeenMs: seen, hbPaged: !ok });
  return ok;
}

/**
 * rev 21 resume check (verifier side, independent of the signer): walk the off-host chain from seq 1 to its
 * current tip verifying every line hash and link, and require the line at `seq` to hash to `head`.
 */
/** R62-P3-2: does the chain, after line afterSeq, hold auto-resume-tamper for this attestation hash? (links checked) */
export async function resumeAppliedAfter(chain: AuditSink, afterSeq: number, attestHash: string, maxLines = 1_000_000): Promise<boolean> {
  let prev = "0".repeat(64), n = 0;
  for (;;) {
    const raw = await chain.at(n + 1);
    if (raw === null) return false;
    const [line, h] = raw.split("\t");
    const ev = JSON.parse(line ?? "{}") as { seq?: number; prev?: string; kind?: string; msgHash?: string };
    if (!line || hashOf(line) !== h || ev.seq !== n + 1 || ev.prev !== prev) throw new Error(`chain link broken at seq ${n + 1}`);
    n += 1; prev = h!;
    if (n > afterSeq && ev.kind === "auto-resume-tamper" && ev.msgHash === attestHash) return true;
    if (n >= maxLines) throw new Error("chain too long");
  }
}

export async function verifyChainHead(chain: AuditSink, seq: number, head: string, maxLines = 1_000_000): Promise<{ tip: number }> {
  let prev = "0".repeat(64), n = 0, found = false;
  for (;;) {
    const raw = await chain.at(n + 1);
    if (raw === null) break;
    const [line, h] = raw.split("\t");
    const ev = JSON.parse(line ?? "{}") as { seq?: number; prev?: string };
    if (!line || hashOf(line) !== h || ev.seq !== n + 1 || ev.prev !== prev) throw new Error(`chain link broken at seq ${n + 1}`);
    n += 1; prev = h!;
    if (n === seq) { if (h !== head) throw new Error(`chain line ${seq} does not hash to the signer's head`); found = true; }
    if (n >= maxLines) throw new Error("chain too long");
  }
  if (!found) throw new Error(`chain has no line ${seq} (tip ${n})`);
  return { tip: n };
}


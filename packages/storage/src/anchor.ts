/**
 * R65-P3-4 (R25-P2-1 follow-up): the monitor anchors the append-only tables to an off-host chain (B2 Object Lock)
 * on every tick, and pages when the DB went backwards since the last anchor. This catches what no in-DB check can:
 * a superuser wiping or rewriting mr_config_audit / mr_pause_log / mr_resume_nonce / mr_release_nonce (replica
 * mode skips every trigger).
 *
 * Per table, the anchor holds: count, max seq, a hash of all rows, and a "settled" prefix: count + hash of the rows
 * older than (DB now - 10 min). The next tick re-hashes exactly that prefix (same cutoff). A deleted, changed or
 * back-dated old row changes it. Newer rows may still be landing (open transactions), so they are only counted.
 * A regression is paged and NOT anchored over, so the page repeats until someone acts.
 *
 * Chain line: JSON {v, kind, seq, prev, at, network, tables} TAB sha256(JSON) TAB base64 Ed25519 signature.
 * prev = the previous line's hash, and the head must link to seq - 1. An empty chain below the pinned minimum means
 * it was wiped or swapped.
 *
 * R66-P3-3: every line is SIGNED by a key that is not on the DB host (MainNet: a Cloud KMS Ed25519 key the monitor's
 * service account may only sign with; TestNet may use a software key). The signed message binds the key to the
 * network, the sequence and the line hash (anchorSigMsg), so a line can't be replayed at another seq. The head AND
 * head-1 are both verified against the pinned public key, and head-1 -> head must be monotone (per table count and
 * max seq never lower, `at` strictly later): someone with B2 write access but without the key can't append a forged
 * head, and a forged pair can't roll the facts back. Prefix, minimum sequence, retention floor (>= 365 d) and the
 * public key are pinned per network in deploy/integrity-manifest.json (ANCHOR_PINS).
 */
import { createPrivateKey, createPublicKey, sign as edSign, verify as edVerify, type KeyObject } from "node:crypto";
import { closeSync, existsSync, fsyncSync, openSync, readFileSync, writeSync } from "node:fs";
import type pg from "pg";
import { SinkBindingError, type AuditSink } from "./b2-sink.js";

export const ANCHOR_SETTLE_S = 600;
/** table -> ORDER BY (stable, unique), the insert-time column, and the monotone "seq" column (null: none). */
export const ANCHOR_TABLES = {
  mr_config_audit: { order: "seq", ts: "at", seq: "seq" },
  mr_pause_log: { order: "network, pause_seq", ts: "paused_at", seq: "pause_seq" },
  mr_resume_nonce: { order: "used_at, nonce", ts: "used_at", seq: "pause_seq" },
  mr_release_nonce: { order: "used_at, nonce", ts: "used_at", seq: null },
} as const;
export type AnchorTable = keyof typeof ANCHOR_TABLES;
export interface TableAnchor { count: number; maxSeq: number; hash: string; settled: { cutoff: string; count: number; hash: string } }
export interface AnchorFacts { network: string; at: string; tables: Partial<Record<AnchorTable, TableAnchor>> }
export interface AnchorLine extends AnchorFacts { v: 1; kind: "mr-monitor-anchor"; seq: number; prev: string }

import { sha256hex as sha } from "./hash.js";

/** R66-P3-3: per-network anchor pins (copied into deploy/integrity-manifest.json by the manifest generator). */
/** R69-P3-1: `skip` = (object key, sha256 of its stored bytes) of reviewed bad objects the B2 sink may step past. */
export interface AnchorSkip { key: string; sha256: string }
/** R70-P3-1: `requireSigned` = unsigned (self-hashed only) lines are never acceptable on this network; MainNet must be true. */
export interface AnchorPin { prefix: string; minSeq: number; retainDaysMin: number; pubkey: string | null; skip: AnchorSkip[]; requireSigned: boolean }
export const ANCHOR_RETAIN_DAYS_MIN = 365;
export const ANCHOR_PINS: Record<"mainnet" | "testnet", AnchorPin> = {
  // pubkey: base64 raw 32-byte Ed25519 key of the anchor signing key; null until the key exists (MainNet pages until pinned)
  mainnet: { prefix: "mr-monitor-anchor/mainnet/", minSeq: 0, retainDaysMin: ANCHOR_RETAIN_DAYS_MIN, pubkey: null, skip: [], requireSigned: true },
  testnet: { prefix: "mr-monitor-anchor/testnet/", minSeq: 0, retainDaysMin: ANCHOR_RETAIN_DAYS_MIN, pubkey: null, skip: [], requireSigned: false },
};
/** Signs anchor lines; must not live on the DB host (MainNet). */
export interface AnchorSigner { sign(msg: Uint8Array): Promise<Uint8Array> }
/** R70-P3-1: are unsigned lines refused on this network? MainNet always (fail closed), else the pin's flag. */
export const anchorRequiresSig = (network: string | undefined, pin?: Pick<AnchorPin, "requireSigned"> | null) => network === "mainnet" || pin?.requireSigned === true;
/**
 * R71-P3-1: resolve the manifest-pinned (key, sha256) skips against the sink. A seq is stepped over only if its
 * object exists AND the sha256 of its stored bytes equals the pin. Every pin pages on every tick:
 *  - matched: "stepping over manifest-pinned object at seq N (key + sha256 matched; ...)" (the plant stays visible, not only on the first tick)
 *  - absent (speculative pin) / sha mismatch / unparseable key: a loud page and the seq is NOT stepped over.
 */
export async function anchorResolveSkips(sink: AuditSink, pin: Pick<AnchorPin, "skip"> | null | undefined): Promise<{ seqs: Set<number>; pages: string[] }> {
  const seqs = new Set<number>();
  const pages: string[] = [];
  for (const k of pin?.skip ?? []) {
    const m = /\/(\d{12})\.jsonl$/.exec(k.key);
    const name = k.key.split("/").at(-1) ?? "?";
    if (!m || !/^[0-9a-f]{64}$/i.test(k.sha256)) { pages.push(`anchor: manifest skip pin ${name} is malformed (refused, not stepped over)`); continue; }
    const seq = 999_999_999_999 - Number(m[1]);
    let raw: Uint8Array | null;
    try {
      // R73-P3-1: hash the stored bytes (rawAt); the line fallback is for the TestNet file stand-in only
      if (sink.rawAt) raw = await sink.rawAt(seq);
      else { const l = await sink.at(seq); raw = l === null ? null : Buffer.from(`${l}\n`, "utf8"); }
    } catch (e) { pages.push(`anchor: manifest skip pin seq ${seq} unreadable (${(e as Error).name}; not stepped over)`); continue; }
    if (raw === null) { pages.push(`anchor: manifest skip pin seq ${seq} names no stored object (speculative pin; not stepped over)`); continue; }
    if (sha(raw) !== k.sha256.toLowerCase()) { pages.push(`anchor: manifest skip pin seq ${seq} sha256 does not match the stored object (not stepped over)`); continue; }
    seqs.add(seq);
    pages.push(`anchor: stepping over manifest-pinned object at seq ${seq} (key + sha256 matched; R69-P3-1 repair, pages every tick)`);
  }
  return { seqs, pages };
}
export const ANCHOR_SIG_PREFIX = "MR-ANCHOR-SIG-v1\n";
/** What is signed: prefix, network, seq and the line hash (binds the key to this sequence of this chain). */
export const anchorSigMsg = (network: string, seq: number, hash: string) => Buffer.from(`${ANCHOR_SIG_PREFIX}${network}\n${seq}\n${hash}`, "utf8");
export function verifyAnchorSig(msg: Uint8Array, sig: Uint8Array, pubkey: Uint8Array): boolean {
  if (pubkey.length !== 32 || sig.length !== 64) return false;
  try {
    const k = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(pubkey)]), format: "der", type: "spki" });
    return edVerify(null, msg, k, sig);
  } catch { return false; }
}

/** Current facts; `prev` (the anchored head) makes it re-hash the old settled prefixes at their own cutoffs. */
export async function anchorFacts(pool: pg.Pool, network: string, prev?: AnchorFacts | null): Promise<{ facts: AnchorFacts; prevSettled: Partial<Record<AnchorTable, { count: number; hash: string }>> }> {
  const c = await pool.connect();
  try {
    await c.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
    await c.query("SET LOCAL TimeZone = 'UTC'"); // row text (timestamps) must not depend on the session
    const now = (await c.query<{ n: string; cut: string }>(`SELECT to_char(clock_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS n,
      to_char((clock_timestamp() - make_interval(secs => ${ANCHOR_SETTLE_S})) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS cut`)).rows[0]!;
    const tables: AnchorFacts["tables"] = {};
    const prevSettled: Partial<Record<AnchorTable, { count: number; hash: string }>> = {};
    const agg = (t: string, order: string, where: string) => `SELECT count(*)::int AS n, coalesce(md5(string_agg(md5(x::text), ',' ORDER BY ${order})), '') AS h FROM public.${t} x ${where}`;
    for (const [t, d] of Object.entries(ANCHOR_TABLES) as Array<[AnchorTable, (typeof ANCHOR_TABLES)[AnchorTable]]>) {
      if (!(await c.query<{ ok: boolean }>("SELECT to_regclass($1) IS NOT NULL AS ok", [`public.${t}`])).rows[0]!.ok) continue;
      const all = (await c.query<{ n: number; h: string }>(agg(t, d.order, ""))).rows[0]!;
      const mx = d.seq ? Number((await c.query<{ m: string }>(`SELECT coalesce(max(${d.seq}), 0)::text AS m FROM public.${t}`)).rows[0]!.m) : all.n;
      const st = (await c.query<{ n: number; h: string }>(agg(t, d.order, `WHERE x.${d.ts} <= $1::timestamptz`), [now.cut])).rows[0]!;
      tables[t] = { count: all.n, maxSeq: mx, hash: all.h, settled: { cutoff: now.cut, count: st.n, hash: st.h } };
      const p = prev?.tables[t];
      if (p) {
        const ps = (await c.query<{ n: number; h: string }>(agg(t, d.order, `WHERE x.${d.ts} <= $1::timestamptz`), [p.settled.cutoff])).rows[0]!;
        prevSettled[t] = { count: ps.n, hash: ps.h };
      }
    }
    await c.query("COMMIT");
    return { facts: { network, at: now.n, tables }, prevSettled };
  } catch (e) {
    await c.query("ROLLBACK").catch(() => undefined);
    throw e;
  } finally { c.release(); }
}

/** Regressions of `cur` against the anchored `prev` (empty = fine). */
export function anchorReasons(prev: AnchorFacts | null, cur: AnchorFacts, prevSettled: Partial<Record<AnchorTable, { count: number; hash: string }>>): string[] {
  if (!prev) return [];
  const out: string[] = [];
  if (prev.network !== cur.network) out.push(`anchor: chain is for ${prev.network}, this DB is ${cur.network}`);
  for (const [t, p] of Object.entries(prev.tables) as Array<[AnchorTable, TableAnchor]>) {
    const c = cur.tables[t];
    if (!c) { out.push(`anchor: ${t} is gone (anchored ${p.count} rows)`); continue; }
    if (c.count < p.count) out.push(`anchor: ${t} has ${c.count} rows, anchored ${p.count} (rows deleted)`);
    if (c.maxSeq < p.maxSeq) out.push(`anchor: ${t} max seq ${c.maxSeq} is below the anchored ${p.maxSeq}`);
    const s = prevSettled[t];
    if (!s || s.count !== p.settled.count || s.hash !== p.settled.hash) {
      out.push(`anchor: ${t} rows older than ${p.settled.cutoff} changed (anchored ${p.settled.count} rows / ${p.settled.hash.slice(0, 12)}, now ${s?.count ?? "?"} / ${(s?.hash ?? "").slice(0, 12)})`);
    }
  }
  return out;
}

export class AnchorChainError extends Error {}
/** R69-P3-1: does a stored line parse as an anchor line of this network (and carry a valid signature when pinned)? */
export function anchorLineAcceptable(l: string, pubkey?: Uint8Array, network?: string, requireSigned = network === "mainnet"): boolean {
  // R70-P3-1: once signatures are required (always on MainNet), a merely self-hashed line is never acceptable
  if ((requireSigned || network === "mainnet") && !pubkey) return false;
  const [j, h, sg] = l.split("\t");
  if (!j || !h || sha(j) !== h) return false;
  let line: AnchorLine;
  try { line = JSON.parse(j) as AnchorLine; } catch { return false; }
  if (line.kind !== "mr-monitor-anchor" || !Number.isSafeInteger(line.seq)) return false;
  if (network && line.network !== network) return false;
  if (pubkey && (!sg || !verifyAnchorSig(anchorSigMsg(network ?? line.network, line.seq, h), Buffer.from(sg, "base64"), pubkey))) return false;
  return true;
}
/** Opens the anchor chain head (verifies its hash, its link to seq - 1 and the pinned minimum). */
export async function anchorHead(sink: AuditSink, minSeq = 0, pubkey?: Uint8Array, network?: string, requireSigned = network === "mainnet", skipPins?: Pick<AnchorPin, "skip"> | null): Promise<{ seq: number; hash: string; facts: AnchorFacts | null; pages: string[] }> {
  // R74-P3-3: no raw seq set on the exported surface; step-overs only via (key, sha256) pins resolved against the stored bytes
  const rs = await anchorResolveSkips(sink, skipPins);
  return { ...(await anchorHeadAt(sink, minSeq, pubkey, network, rs.seqs, requireSigned)), pages: rs.pages };
}
async function anchorHeadAt(sink: AuditSink, minSeq: number, pubkey: Uint8Array | undefined, network: string | undefined, skipSeqs: ReadonlySet<number>, requireSigned: boolean): Promise<{ seq: number; hash: string; facts: AnchorFacts | null }> {
  if ((requireSigned || network === "mainnet") && !pubkey) throw new AnchorChainError("anchor public key is required on this network but not pinned: unsigned lines are refused (R70-P3-1)");
  const last = await sink.last();
  if (!last) {
    if (minSeq > 0) throw new AnchorChainError(`anchor chain is empty but the pinned minimum sequence is ${minSeq}: wiped or swapped`);
    return { seq: 0, hash: "0".repeat(64), facts: null };
  }
  const parse = (l: string | null, what: string) => {
    const [j, h, sg] = (l ?? "").split("\t");
    if (!j || !h || sha(j) !== h) return null;
    let line: AnchorLine;
    try { line = JSON.parse(j) as AnchorLine; } catch { return null; }
    if (line.kind !== "mr-monitor-anchor" || !Number.isSafeInteger(line.seq)) return null;
    // R66-P3-3: signed by the pinned off-DB-host key, over (network, seq, hash)
    if (pubkey && (!sg || !verifyAnchorSig(anchorSigMsg(network ?? line.network, line.seq, h), Buffer.from(sg, "base64"), pubkey))) {
      throw new AnchorChainError(`anchor ${what} (seq ${line.seq}) is not signed by the pinned anchor key`);
    }
    if (network && line.network !== network) throw new AnchorChainError(`anchor ${what} is for ${line.network}, expected ${network}`);
    return { line, hash: h };
  };
  const head = parse(last, "head");
  if (!head) throw new AnchorChainError("anchor head line is corrupt");
  if (head.line.seq < minSeq) throw new AnchorChainError(`anchor head sequence ${head.line.seq} is below the pinned minimum ${minSeq}: rolled back or swapped`);
  if (head.line.seq > 1) {
    // R70-P3-1: the predecessor is head-1, stepping down over manifest-pinned skipped seqs (a pinned junk object
    // that append had to step over). A pinned seq is used only if its line is the one head.prev links to.
    let want = head.line.seq - 1;
    let p: ReturnType<typeof parse> = null;
    for (;;) {
      if (skipSeqs.has(want)) {
        let raw: string | null = null;
        try { raw = await sink.at(want); } catch { raw = null; }
        let cand: ReturnType<typeof parse> = null;
        try { cand = raw ? parse(raw, "head-1") : null; } catch { cand = null; }
        if (cand && cand.line.seq === want && cand.hash === head.line.prev) { p = cand; break; }
        if (want <= 1) break;
        want -= 1;
        continue;
      }
      p = parse(await sink.at(want), "head-1");
      break;
    }
    if (!p || p.line.seq !== want || head.line.prev !== p.hash) throw new AnchorChainError(`anchor head (seq ${head.line.seq}) does not link to seq ${want}`);
    // R66-P3-3: head-1 -> head never goes backwards
    const bad: string[] = [];
    if (!(Date.parse(head.line.at) > Date.parse(p.line.at))) bad.push("at");
    for (const [t, a] of Object.entries(p.line.tables) as Array<[AnchorTable, TableAnchor]>) {
      const b = head.line.tables[t];
      if (!b || b.count < a.count || b.maxSeq < a.maxSeq || b.settled.count < a.settled.count) bad.push(t);
    }
    if (bad.length) throw new AnchorChainError(`anchor head (seq ${head.line.seq}) regresses against seq ${want} (${bad.join(", ")})`);
  }
  const { v: _v, kind: _k, seq: _s, prev: _p, ...facts } = head.line;
  return { seq: head.line.seq, hash: head.hash, facts };
}
export async function anchorLine(seq: number, prev: string, f: AnchorFacts, signer?: AnchorSigner): Promise<string> {
  const j = JSON.stringify({ v: 1, kind: "mr-monitor-anchor", seq, prev, ...f } satisfies AnchorLine);
  const h = sha(j);
  if (!signer) return `${j}\t${h}`;
  const sig = await signer.sign(anchorSigMsg(f.network, seq, h));
  return `${j}\t${h}\t${Buffer.from(sig).toString("base64")}`;
}

/** One monitor tick: verify against the head, then anchor the current state (only when nothing regressed). */
export async function anchorTick(a: { pool: pg.Pool; network: string; sink: AuditSink; minSeq?: number; signer?: AnchorSigner; pubkey?: Uint8Array; skipped?: () => string[]; skipPins?: Pick<AnchorPin, "skip"> | null; requireSigned?: boolean }): Promise<{ reasons: string[]; seq: number; anchored: boolean }> {
  // R71-P3-1 / R73-P3-4: the step-over set comes only from pins whose object exists and matches its sha256 (no raw seq set accepted)
  const rs = await anchorResolveSkips(a.sink, a.skipPins);
  const r = await anchorTickInner({ ...a, skipSeqs: rs.seqs });
  const sk = (a.skipped?.() ?? []).map((k) => `anchor: head listing stepped over manifest-pinned object ${k} (key + sha256 matched)`);
  return { ...r, reasons: [...rs.pages, ...sk, ...r.reasons] };
}
async function anchorTickInner(a: { pool: pg.Pool; network: string; sink: AuditSink; minSeq?: number; signer?: AnchorSigner; pubkey?: Uint8Array; skipSeqs?: ReadonlySet<number>; requireSigned?: boolean }): Promise<{ reasons: string[]; seq: number; anchored: boolean }> {
  if (a.requireSigned && a.network !== "mainnet" && (!a.signer || !a.pubkey)) {
    return { reasons: ["anchor: the manifest requires signed anchors (requireSigned) but no signing key / pinned public key is configured (R70-P3-1)"], seq: 0, anchored: false };
  }
  if (a.network === "mainnet" && (!a.signer || !a.pubkey)) {
    return { reasons: ["anchor: no signing key / pinned public key (R66-P3-3): unsigned anchors are refused on MainNet"], seq: 0, anchored: false };
  }
  if (!!a.signer !== !!a.pubkey) return { reasons: ["anchor: a signing key needs its pinned public key (and vice versa)"], seq: 0, anchored: false };
  let head;
  try { head = await anchorHeadAt(a.sink, a.minSeq ?? 0, a.pubkey, a.network, a.skipSeqs ?? new Set(), a.requireSigned ?? a.network === "mainnet"); } catch (e) {
    return { reasons: [e instanceof AnchorChainError || e instanceof SinkBindingError ? `anchor: ${e.message}` : `anchor: chain unreadable (${(e as Error).name})`], seq: 0, anchored: false };
  }
  const { facts, prevSettled } = await anchorFacts(a.pool, a.network, head.facts);
  const reasons = anchorReasons(head.facts, facts, prevSettled);
  if (reasons.length) return { reasons, seq: head.seq, anchored: false };
  // R70-P3-1: step over manifest-pinned skipped seqs (their keys are Object-Locked junk); prev stays the head
  let next = head.seq + 1;
  while (a.skipSeqs?.has(next)) next += 1;
  try {
    const line = await anchorLine(next, head.hash, facts, a.signer);
    // self-verify before appending (a wrong key would otherwise break the chain for the next tick)
    if (a.pubkey && !verifyAnchorSig(anchorSigMsg(a.network, next, line.split("\t")[1]!), Buffer.from(line.split("\t")[2] ?? "", "base64"), a.pubkey)) {
      return { reasons: ["anchor: the signing key does not match the pinned public key"], seq: head.seq, anchored: false };
    }
    await a.sink.append(line);
  } catch (e) {
    return { reasons: [`anchor: append failed (${(e as Error).name})`], seq: head.seq, anchored: false };
  }
  return { reasons: [], seq: next, anchored: true };
}

/** TESTNET-ONLY local stand-in for the B2 anchor chain (an O_APPEND file; not off-host, not immutable). */
export class AnchorFileStandIn implements AuditSink {
  constructor(private readonly file: string, network: string) {
    if (network !== "testnet") throw new Error("the anchor file stand-in is TESTNET-ONLY");
  }
  private lines(): string[] { return existsSync(this.file) ? readFileSync(this.file, "utf8").split("\n").filter(Boolean) : []; }
  async append(line: string): Promise<void> {
    if (line.includes("\n")) throw new Error("line contains a newline");
    const fd = openSync(this.file, "a", 0o640);
    try { writeSync(fd, line + "\n"); fsyncSync(fd); } finally { closeSync(fd); }
  }
  async at(seq: number): Promise<string | null> { return this.lines().find((l) => (JSON.parse(l.split("\t")[0]!) as { seq?: number }).seq === seq) ?? null; }
  async last(): Promise<string | null> { return this.lines().at(-1) ?? null; }
}

/** R66-P3-3: TESTNET-ONLY software anchor key (PKCS#8 PEM file). */
export class SoftwareAnchorSigner implements AnchorSigner {
  private readonly key: KeyObject;
  constructor(pem: string, network: string) {
    if (network !== "testnet") throw new Error("the software anchor key is TESTNET-ONLY");
    this.key = createPrivateKey(pem);
    if (this.key.asymmetricKeyType !== "ed25519") throw new Error("anchor key must be Ed25519");
  }
  async sign(msg: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(edSign(null, msg, this.key));
  }
}

/**
 * R66-P3-3: MainNet anchor key in Google Cloud KMS (EC_SIGN_ED25519, HSM), off the DB host. The monitor host's
 * service account holds only cloudkms.cryptoKeyVersions.useToSign on this one version; the token comes from the
 * metadata server (no key file). keyVersion = projects/../cryptoKeyVersions/N.
 */
export class GcpKmsAnchorSigner implements AnchorSigner {
  constructor(private readonly keyVersion: string, private readonly f: typeof fetch = fetch) {
    if (!/^projects\/[a-z][a-z0-9-]{4,28}[a-z0-9]\/locations\/[a-z0-9-]+\/keyRings\/[A-Za-z0-9_-]+\/cryptoKeys\/[A-Za-z0-9_-]+\/cryptoKeyVersions\/[0-9]+$/.test(keyVersion)) {
      throw new Error("MONITOR_ANCHOR_KMS_KEY must be a Cloud KMS cryptoKeyVersion resource name");
    }
  }
  async sign(msg: Uint8Array): Promise<Uint8Array> {
    const t = await this.f("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", { headers: { "Metadata-Flavor": "Google" } });
    if (!t.ok) throw new Error(`anchor KMS: metadata token HTTP ${t.status}`);
    const tok = ((await t.json()) as { access_token?: string }).access_token;
    if (!tok) throw new Error("anchor KMS: no access token");
    const r = await this.f(`https://cloudkms.googleapis.com/v1/${this.keyVersion}:asymmetricSign`, {
      method: "POST", headers: { authorization: `Bearer ${tok}`, "content-type": "application/json" }, body: JSON.stringify({ data: Buffer.from(msg).toString("base64") }),
    });
    if (!r.ok) throw new Error(`anchor KMS: asymmetricSign HTTP ${r.status}`);
    const sig = Buffer.from(((await r.json()) as { signature?: string }).signature ?? "", "base64");
    if (sig.length !== 64) throw new Error("anchor KMS: signature is not 64 bytes");
    return new Uint8Array(sig);
  }
}

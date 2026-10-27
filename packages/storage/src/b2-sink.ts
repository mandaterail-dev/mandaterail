/**
 * Off-host audit sink on Backblaze B2 through its S3-compatible API with Object Lock (rev 10 §13 "Monitoring").
 * - One object per line (PutObject), written with x-amz-object-lock-mode=COMPLIANCE and a retain-until date, so
 *   not even the B2 account owner can delete or overwrite it before the retention ends. The bucket must be
 *   created with Object Lock enabled (versioning on); the signer's application key has only writeFiles,
 *   listFiles and readFiles on that one bucket (no deleteFiles, no bypassGovernance).
 * - Keys are `<prefix>/<inverted zero-padded seq>.jsonl`, so ListObjectsV2(max-keys=1) returns the head.
 * - Content-MD5 is sent (required by S3 for Object Lock puts).
 * - R45-P3-1: Backblaze B2 does NOT implement conditional writes (If-None-Match / If-Match return 501 Not
 *   Implemented; Proxmox and ZeroFS ship a "backblaze" quirk for it). So the default mode is check-then-put: GET the
 *   seq's key first; identical bytes = the earlier PUT landed and only the ack was lost (success, nothing written);
 *   different bytes = refuse. On S3 proper, mode "if-none-match" is used, and a 501 falls back to check-then-put.
 *   With versioning on (Object Lock requires it), a second writer could still add a version under an existing key;
 *   open() refuses a head key with more than one distinct version (ETag) — see headVersionsDistinct().
 * Credentials come from the environment file (0600, root:mr-signer); they are never logged or put in errors.
 * Hand-written SigV4 (no SDK dependency on the signer host).
 */
import { createHash, createHmac } from "node:crypto";
/** Off-host append-only line store (same shape as the signer's AuditSink). R65-P3-4: moved here from
 *  packages/signer/src/sinks/s3.ts so the monitor (this package) can anchor to B2 too; the signer re-exports it. */
export interface AuditSink {
  append(line: string): Promise<void>;
  last(): Promise<string | null>;
  at(seq: number): Promise<string | null>;
  /** R71-P3-1: the exact stored bytes of the object for `seq` (no parse / binding check; null = absent). */
  rawAt?(seq: number): Promise<Uint8Array | null>; // R73-P3-1: bytes, never decoded text
}

export interface S3SinkConfig {
  endpoint: string; // https://s3.<region>.backblazeb2.com
  region: string; // e.g. us-west-004
  bucket: string;
  prefix: string; // e.g. mr-signer/testnet
  retainDays: number; // Object Lock COMPLIANCE retention
  conditionalWrites?: "check-then-put" | "if-none-match"; // B2: check-then-put (default)
  accessKeyId: string;
  secretAccessKey: string;
  timeoutMs?: number;
  /**
   * R69-P3-1 repair path (replaces R67's skipMisboundKeys): (key, sha256 of the exact stored object bytes) pairs, pinned
   * in the sha256-pinned integrity manifest (`anchor.<network>.skip`). last() steps past a listed object only when it
   * matches BOTH the key and the sha256 AND it is bad: misbound, or rejected by `accept` (parse / signature). A listed
   * object that is valid is never skipped (no rollback through the list); a pre-listed future key can't match an
   * unknown sha256. Every skip is reported through onSkip (the monitor pages it every tick). minSeq stays pinned.
   */
  skipPinned?: ReadonlyArray<{ key: string; sha256: string }>;
  /** R69-P3-1: line validator (parse + signature) used to decide whether a pinned object is bad. Default: accept. */
  accept?: (line: string) => boolean;
  /** R69-P3-1: called with the key suffix of every skipped object (never credentials). */
  onSkip?: (keySuffix: string) => void;
}
type Fetch = typeof fetch;

const SEQ_MAX = 999_999_999_999;
export const seqKey = (prefix: string, seq: number) => `${prefix}/${String(SEQ_MAX - seq).padStart(12, "0")}.jsonl`;
/** seq of an `json\t…` line, or NaN (never equals a key's seq) */
export function lineSeq(line: string): number {
  try { const v = (JSON.parse(line.split("\t")[0]!) as { seq?: unknown }).seq; return typeof v === "number" && Number.isSafeInteger(v) ? v : NaN; } catch { return NaN; }
}
import { sha256hex } from "./hash.js";
const hmac = (k: Buffer | string, d: string) => createHmac("sha256", k).update(d).digest();
// RFC 3986 encoding as SigV4 requires
const enc = (s: string, slash = true) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase()).replace(slash ? /%2F/g : /$^/, "/");

export class SinkError extends Error {}
/** R67-P3-2: an object key not bound to its line's seq (message names only the key suffix, never credentials) */
export class SinkBindingError extends SinkError {}

export function sigV4(c: Pick<S3SinkConfig, "region" | "accessKeyId" | "secretAccessKey">, method: string, url: URL, headers: Record<string, string>, payload: Buffer | string, now = new Date(), service = "s3"): Record<string, string> {
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const day = amzDate.slice(0, 8);
  const h: Record<string, string> = { ...headers, host: url.host, "x-amz-date": amzDate, "x-amz-content-sha256": sha256hex(payload) };
  const names = Object.keys(h).map((k) => k.toLowerCase()).sort();
  const lower = Object.fromEntries(Object.entries(h).map(([k, v]) => [k.toLowerCase(), String(v).trim()]));
  const query = [...url.searchParams.entries()].map(([k, v]) => [enc(k, false), enc(v, false)]).sort((a, b) => (a[0]! < b[0]! ? -1 : a[0]! > b[0]! ? 1 : a[1]! < b[1]! ? -1 : 1)).map(([k, v]) => `${k}=${v}`).join("&");
  const canonical = [method, enc(decodeURIComponent(url.pathname)), query, names.map((n) => `${n}:${lower[n]}\n`).join(""), names.join(";"), lower["x-amz-content-sha256"]].join("\n");
  const scope = `${day}/${c.region}/${service}/aws4_request`;
  const toSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256hex(canonical)].join("\n");
  const kSig = hmac(hmac(hmac(hmac("AWS4" + c.secretAccessKey, day), c.region), service), "aws4_request");
  const sig = createHmac("sha256", kSig).update(toSign).digest("hex");
  return { ...h, authorization: `AWS4-HMAC-SHA256 Credential=${c.accessKeyId}/${scope}, SignedHeaders=${names.join(";")}, Signature=${sig}` };
}

export class B2ObjectLockSink implements AuditSink {
  constructor(private readonly c: S3SinkConfig, private readonly f: Fetch = fetch, private readonly now: () => Date = () => new Date()) {
    if (!/^https:\/\//.test(c.endpoint) && !/^http:\/\/127\.0\.0\.1[:/]/.test(c.endpoint)) throw new SinkError("endpoint must be https");
    if (!(c.retainDays >= 1)) throw new SinkError("retainDays must be >= 1");
    this.mode = c.conditionalWrites ?? "check-then-put";
  }

  private url(key: string, q: Record<string, string> = {}): URL {
    const u = new URL(`${this.c.endpoint.replace(/\/$/, "")}/${this.c.bucket}/${key.split("/").map((p) => enc(p, false)).join("/")}`.replace(/\/$/, key ? "" : "/"));
    for (const [k, v] of Object.entries(q)) u.searchParams.set(k, v);
    return u;
  }

  private async req(method: string, u: URL, headers: Record<string, string>, body: Buffer | string = ""): Promise<{ status: number; text: string; bytes: Buffer }> {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), this.c.timeoutMs ?? 10_000);
    try {
      const h = sigV4(this.c, method, u, headers, body, this.now());
      delete (h as Record<string, string>).host;
      const r = await this.f(u, { method, headers: h, body: method === "PUT" ? body : undefined, redirect: "error", signal: ctl.signal } as RequestInit);
      // R73-P3-1: keep the exact stored bytes (skip-pin sha); text is the UTF-8 decoding of the same bytes
      const bytes = Buffer.from(await r.arrayBuffer());
      return { status: r.status, text: bytes.toString("utf8"), bytes };
    } catch (e) {
      throw new SinkError(`s3 ${method} failed: ${(e as Error).name}`); // no URL/credential detail
    } finally {
      clearTimeout(t);
    }
  }

  private mode: "check-then-put" | "if-none-match";

  async append(line: string): Promise<void> {
    const [json] = line.split("\t");
    const seq = (JSON.parse(json!) as { seq?: unknown }).seq;
    if (typeof seq !== "number" || !Number.isInteger(seq) || seq < 1 || seq > SEQ_MAX) throw new SinkError("line has no valid seq");
    const body = Buffer.from(line + "\n", "utf8");
    const key = seqKey(this.c.prefix, seq);
    if (this.mode === "check-then-put") {
      const g = await this.req("GET", this.url(key), {});
      if (g.status === 200) {
        if (g.text === body.toString("utf8")) return; // lost ack on an earlier PUT: already stored, identical
        throw new SinkError(`seq ${seq} is already stored with different content`);
      }
      if (g.status !== 404) throw new SinkError(`s3 get status ${g.status}`);
    }
    const retain = new Date(this.now().getTime() + this.c.retainDays * 86_400_000).toISOString().replace(/\.\d{3}Z$/, "Z");
    const headers: Record<string, string> = {
      "content-type": "application/x-ndjson", "content-md5": createHash("md5").update(body).digest("base64"),
      "x-amz-object-lock-mode": "COMPLIANCE", "x-amz-object-lock-retain-until-date": retain,
    };
    if (this.mode === "if-none-match") headers["if-none-match"] = "*";
    const r = await this.req("PUT", this.url(key), headers, body);
    if (r.status === 501 && this.mode === "if-none-match") { this.mode = "check-then-put"; return this.append(line); }
    if (r.status === 412) {
      const g = await this.req("GET", this.url(key), {});
      if (g.status === 200 && g.text === body.toString("utf8")) return;
      throw new SinkError(`s3 put status 412 (seq ${seq} already stored with different content)`);
    }
    if (r.status !== 200) throw new SinkError(`s3 put status ${r.status}`);
  }

  async rawAt(seq: number): Promise<Uint8Array | null> {
    const key = seqKey(this.c.prefix, seq);
    const g = await this.req("GET", this.url(key), {});
    if (g.status === 404) return null;
    if (g.status !== 200) throw new SinkError(`s3 get status ${g.status}`);
    if ((await this.headVersionsDistinct(key)) > 1) throw new SinkError(`key for seq ${seq} has more than one distinct version: second writer`);
    return g.bytes;
  }

  async at(seq: number): Promise<string | null> {
    const key = seqKey(this.c.prefix, seq);
    const g = await this.req("GET", this.url(key), {});
    if (g.status === 404) return null;
    // R46-P3: seq - 1 (and any key read through at()) gets the same second-writer check as the head
    if (g.status === 200 && (await this.headVersionsDistinct(key)) > 1) throw new SinkError(`key for seq ${seq} has more than one distinct version: second writer`);
    if (g.status !== 200) throw new SinkError(`s3 get status ${g.status}`);
    const line = g.text.replace(/\n$/, "");
    if (lineSeq(line) !== seq) throw new SinkBindingError(`key for seq ${seq} holds a line for another seq`); // R67-P3-2
    return line;
  }

  /** Distinct ETags among the versions of one key (ListObjectVersions). More than one = a second writer. */
  async headVersionsDistinct(key: string): Promise<number> {
    const u = this.url("", { versions: "", prefix: key });
    const r = await this.req("GET", u, {});
    if (r.status !== 200) throw new SinkError(`s3 list versions status ${r.status}`);
    const tags = new Set([...r.text.matchAll(/<Version>[\s\S]*?<Key>([^<]+)<\/Key>[\s\S]*?<ETag>([^<]+)<\/ETag>[\s\S]*?<\/Version>/g)].filter((m) => m[1] === key).map((m) => m[2]));
    return tags.size;
  }

  async last(): Promise<string | null> {
    const pins = new Map((this.c.skipPinned ?? []).map((p) => [p.key, p.sha256.toLowerCase()]));
    const u = this.url("", { "list-type": "2", prefix: this.c.prefix + "/", "max-keys": String(pins.size + 1) });
    const l = await this.req("GET", u, {});
    if (l.status !== 200) throw new SinkError(`s3 list status ${l.status}`);
    for (const m of l.text.matchAll(/<Key>([^<]+)<\/Key>/g)) {
      const key = m[1]!.replace(/&amp;/g, "&");
      if ((await this.headVersionsDistinct(key)) > 1) throw new SinkError(`head key has more than one distinct version: second writer`);
      const g = await this.req("GET", this.url(key), {});
      if (g.status !== 200) throw new SinkError(`s3 get status ${g.status}`);
      const line = g.text.replace(/\n$/, "");
      const suffix = key.slice(this.c.prefix.length + 1);
      // R67-P3-2: the head object's key must be the key of the seq its line carries (no replay under a first-sorting key)
      const bound = key === seqKey(this.c.prefix, lineSeq(line));
      let ok = bound;
      if (bound) { try { ok = this.c.accept ? this.c.accept(line) : true; } catch { ok = false; } }
      // R69-P3-1: a bad object is skipped only when pinned by exact key AND sha256 of its stored bytes
      if (!ok && pins.get(key) === sha256hex(g.bytes)) { this.c.onSkip?.(suffix); continue; }
      if (bound) return line; // valid, or bad but unpinned (anchorHead refuses it as corrupt / unsigned)
      throw new SinkBindingError(`head key ${suffix} does not match its line's seq (planted or replayed object)`);
    }
    return null;
  }
}

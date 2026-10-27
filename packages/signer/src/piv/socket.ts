/**
 * mr-piv-sign transport (R43-P2-4). Production: systemd socket activation, one process per connection
 * (deploy/signer/mr-piv-sign.socket: SocketUser=mr-piv, SocketGroup=mr-signer, SocketMode=0660, Accept=yes,
 * MaxConnections=1), each connection passed through mr-peercred-gate (ops/signer/peercred-gate.c), which checks
 * SO_PEERCRED uid == mr-signer before exec'ing `mr-piv-sign --stdio`. Exactly one JSON line in, one line out.
 */
import net from "node:net";
import type { Readable, Writable } from "node:stream";
import type { HelperLike } from "../signer.js";
import type { SignedRequest } from "../requests.js";

const MAX = 32_768;

/** Reads exactly one line (R43-P3: never re-parses later chunks), answers once, closes. */
export function serveOnce(h: HelperLike & { counter?(): number }, input: Readable, output: Writable, readTimeoutMs = 10_000): Promise<void> {
  return new Promise((resolve) => {
    let buf = "";
    let done = false;
    // R44-P3: a peer that connects and never sends a line can't hold the single MaxConnections=1 slot
    const timer = setTimeout(() => finish({ error: "read timeout" }), readTimeoutMs);
    const finish = (v: unknown) => { if (done) return; done = true; clearTimeout(timer); input.pause(); output.end(JSON.stringify(v) + "\n"); resolve(); };
    input.setEncoding("utf8");
    input.on("data", async (d: string) => {
      if (done) return;
      buf += d;
      if (buf.length > MAX) return finish({ error: "too large" });
      const i = buf.indexOf("\n");
      if (i < 0) return;
      const line = buf.slice(0, i);
      buf = "";
      input.removeAllListeners("data");
      clearTimeout(timer);
      try {
        // rev 21: two ops only, both carrying the requester's own confirm (no unlock / status op)
        const r = JSON.parse(line) as { op?: "sign" | "resume"; msg: string; confirm: SignedRequest };
        if (r.op === "resume") {
          if (!h.signResume) return finish({ error: "resume unsupported" });
          const sig = await h.signResume(Buffer.from(r.msg, "base64"), r.confirm);
          return finish({ sig: Buffer.from(sig).toString("base64"), ...(h.counter ? { counter: h.counter() } : {}) });
        }
        if (r.op !== undefined && r.op !== "sign") return finish({ error: "op" });
        const sig = await h.sign(Buffer.from(r.msg, "base64"), r.confirm);
        finish({ sig: Buffer.from(sig).toString("base64"), ...(h.counter ? { counter: h.counter() } : {}) });
      } catch (e) {
        finish({ error: (e as Error).message });
      }
    });
    input.on("end", () => finish({ error: "no request" }));
  });
}

/** Test/dev server (one serveOnce per connection). Production uses systemd + the peer-uid gate instead. */
export function helperSocketServer(h: HelperLike, sockPath: string): net.Server {
  const srv = net.createServer((c) => { void serveOnce(h, c, c); });
  srv.listen(sockPath);
  return srv;
}

export class HelperSocketClient implements HelperLike {
  private counter: number | undefined;
  constructor(private readonly sockPath: string, private readonly timeoutMs = 30_000) {}
  lastCounter(): number | undefined { return this.counter; }
  private roundTrip(req: unknown): Promise<Record<string, unknown>> {
    return new Promise((resolve, reject) => {
      const c = net.createConnection(this.sockPath);
      let buf = "";
      const t = setTimeout(() => { c.destroy(); reject(new Error("helper timeout")); }, this.timeoutMs);
      c.setEncoding("utf8");
      c.on("data", (d: string) => { buf += d; });
      c.on("error", (e) => { clearTimeout(t); reject(e); });
      c.on("end", () => { clearTimeout(t); try { resolve(JSON.parse(buf) as Record<string, unknown>); } catch { reject(new Error("helper reply")); } });
      c.write(JSON.stringify(req) + "\n");
    });
  }
  async signResume(msg: Uint8Array, confirm: SignedRequest): Promise<Uint8Array> {
    const r = await this.roundTrip({ op: "resume", msg: Buffer.from(msg).toString("base64"), confirm });
    if (typeof r.sig !== "string") throw new Error(`helper refused: ${String(r.error ?? "resume")}`);
    if (typeof r.counter !== "number") throw new Error("helper reply has no state counter");
    this.counter = r.counter;
    return new Uint8Array(Buffer.from(r.sig, "base64"));
  }
  sign(msg: Uint8Array, confirm: SignedRequest): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
      const c = net.createConnection(this.sockPath);
      let buf = "";
      const t = setTimeout(() => { c.destroy(); reject(new Error("helper timeout")); }, this.timeoutMs);
      c.setEncoding("utf8");
      c.on("data", (d: string) => { buf += d; });
      c.on("error", (e) => { clearTimeout(t); reject(e); });
      c.on("end", () => {
        clearTimeout(t);
        try {
          const r = JSON.parse(buf) as { sig?: string; error?: string; counter?: number };
          if (!r.sig) reject(new Error(`helper refused: ${r.error}`));
          else if (typeof r.counter !== "number") reject(new Error("helper reply has no state counter"));
          else { this.counter = r.counter; resolve(new Uint8Array(Buffer.from(r.sig, "base64"))); }
        } catch { reject(new Error("helper reply")); }
      });
      c.write(JSON.stringify({ msg: Buffer.from(msg).toString("base64"), confirm }) + "\n");
    });
  }
}

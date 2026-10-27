/**
 * The only inbound surface: HTTP on the IAP-tunnel / WireGuard address (bind it there; the host firewall allows nothing
 * else). App-level source-IP allowlist on top of the firewall, 64 KiB body cap, JSON only, no redirects.
 *
 * Rev 21 (§23): every route takes a requester-signed request (timestamp window, single-use persisted nonce, per-
 * requester hourly rate; requests.ts) and nothing else. There is no /v1/unlock, no /v1/pause and no route that
 * changes caps or config. Routes: candidate, confirm (releases), status (read-only), resume-candidate,
 * resume-confirm, resume-apply (the automatic 2-of-2 tamper resume). The reason for a refusal is only in the
 * off-host log; the peer learns "refused".
 */
import http from "node:http";
import type { MrSigner } from "./signer.js";

const ROUTES = {
  "/v1/candidate": "candidate", "/v1/confirm": "confirm", "/v1/status": "status",
  "/v1/resume-candidate": "resumeCandidate", "/v1/resume-confirm": "resumeConfirm", "/v1/resume-apply": "resumeApply",
} as const;

export function signerServer(s: MrSigner, opts: { allowIps: string[] }): http.Server {
  return http.createServer(async (req, res) => {
    const ip = (req.socket.remoteAddress ?? "").replace(/^::ffff:/, "");
    const send = (code: number, v: unknown) => { res.writeHead(code, { "content-type": "application/json", "cache-control": "no-store" }); res.end(JSON.stringify(v)); };
    if (!opts.allowIps.includes(ip)) { req.destroy(); return; }
    if (req.method !== "POST" || req.headers["content-type"] !== "application/json") return send(405, { error: "method" });
    const route = (ROUTES as Record<string, (typeof ROUTES)[keyof typeof ROUTES]>)[req.url ?? ""];
    if (!route) return send(404, { error: "route" });
    const chunks: Buffer[] = [];
    let n = 0;
    for await (const c of req) { n += (c as Buffer).length; if (n > 65_536) return send(413, { error: "size" }); chunks.push(c as Buffer); }
    let body: unknown;
    try { body = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { return send(400, { error: "json" }); }
    try {
      send(200, await s[route](body as never));
    } catch (e) {
      // R43-P3: the reason is in the off-host log; the peer only learns that it was refused
      void e;
      send(403, { error: "refused" });
    }
  });
}

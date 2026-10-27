/**
 * Second verifier HTTP surface: POST /v1/cosign; rev 21: POST /v1/resume-cosign (requester-signed); R50-P3: POST /v1/reconcile-status (read-only) and
 * /v1/reconcile-ack (requester-signed). Source-IP allowlist, 64 KiB cap, no reasons returned.
 */
import http from "node:http";
import type { SecondVerifier } from "./verifier.js";
import type { Reconciler } from "./reconcile.js";
import type { RequestAuth } from "../requests.js";

export function verifierServer(v: SecondVerifier, opts: { allowIps: string[]; reconciler?: Reconciler; auth?: RequestAuth }): http.Server {
  return http.createServer(async (req, res) => {
    const ip = (req.socket.remoteAddress ?? "").replace(/^::ffff:/, "");
    const send = (code: number, x: unknown) => { res.writeHead(code, { "content-type": "application/json", "cache-control": "no-store" }); res.end(JSON.stringify(x)); };
    if (!opts.allowIps.includes(ip)) { req.destroy(); return; }
    const routes = ["/v1/cosign", "/v1/resume-cosign", "/v1/resume-observed", "/v1/status", "/v1/reconcile-status", "/v1/reconcile-ack"];
    if (req.method !== "POST" || !routes.includes(req.url ?? "") || req.headers["content-type"] !== "application/json") return send(404, { error: "route" });
    if (req.url !== "/v1/cosign" && req.url !== "/v1/resume-cosign" && req.url !== "/v1/resume-observed" && req.url !== "/v1/status" && (!opts.reconciler || !opts.auth)) return send(404, { error: "route" });
    const chunks: Buffer[] = []; let n = 0;
    for await (const c of req) { n += (c as Buffer).length; if (n > 65_536) return send(413, { error: "size" }); chunks.push(c as Buffer); }
    try {
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      if (req.url === "/v1/cosign") return send(200, await v.cosign(body));
      if (req.url === "/v1/resume-cosign") return send(200, await v.resumeCosign(body));
      if (req.url === "/v1/resume-observed") return send(200, await v.resumeObserved(body));
      if (req.url === "/v1/status") return send(200, await v.status(body));
      if (req.url === "/v1/reconcile-status") return send(200, opts.reconciler!.status());
      return send(200, await opts.reconciler!.acknowledge(body, opts.auth!));
    } catch { send(403, { error: "refused" }); }
  });
}

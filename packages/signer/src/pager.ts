/**
 * Real pager and dead-man ping (rev 10 §13). ntfy: POST https://ntfy.sh/<topic>; the topic is a capability
 * (anyone who knows it can read/publish), so it lives only in the 0600 environment file and is never logged.
 * Errors name the failure, never the topic or URL.
 */
import type { Pager } from "./audit.js";

type Fetch = typeof fetch;

export function ntfyPager(o: { server?: string; topic: string; timeoutMs?: number; fetch?: Fetch }): Pager {
  if (!/^[A-Za-z0-9_-]{16,64}$/.test(o.topic)) throw new Error("ntfy topic must be 16-64 chars of [A-Za-z0-9_-]");
  const base = (o.server ?? "https://ntfy.sh").replace(/\/$/, "");
  if (!/^https:\/\//.test(base) && !/^http:\/\/127\.0\.0\.1[:/]/.test(base)) throw new Error("ntfy server must be https");
  const f = o.fetch ?? fetch;
  return async (subject, body) => {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), o.timeoutMs ?? 10_000);
    try {
      const r = await f(`${base}/${o.topic}`, { method: "POST", headers: { title: subject.replace(/[^\x20-\x7e]/g, "?"), priority: /heartbeat/.test(subject) ? "min" : "high", tags: "rotating_light" }, body: body || subject, redirect: "error", signal: ctl.signal } as RequestInit);
      if (r.status !== 200) throw new Error(`ntfy status ${r.status}`);
    } catch (e) {
      throw new Error(`ntfy publish failed: ${(e as Error).message.replace(o.topic, "<topic>")}`);
    } finally {
      clearTimeout(t);
    }
  };
}

/** Healthchecks.io-style dead-man ping (GET <url>). Optional until a free account exists. */
export function deadManPing(url: string | null, f: Fetch = fetch): () => Promise<void> {
  return async () => {
    if (!url) return;
    const r = await f(url, { method: "GET", redirect: "error", signal: AbortSignal.timeout(10_000) } as RequestInit);
    if (r.status !== 200) throw new Error(`dead-man ping status ${r.status}`);
  };
}

/** Heartbeat timer: runs heartbeat() every intervalMs; never overlaps; returns a stop function. */
export function startHeartbeat(tick: () => Promise<boolean>, intervalMs: number, onResult: (ok: boolean) => void = () => {}): () => void {
  let busy = false;
  const run = async () => {
    if (busy) return;
    busy = true;
    try { onResult(await tick()); } catch { onResult(false); } finally { busy = false; }
  };
  void run();
  const h = setInterval(run, intervalMs);
  h.unref?.();
  return () => clearInterval(h);
}

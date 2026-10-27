/**
 * MandateRail ac2-bridge Hono app (testable; no listen / no startup gates).
 * See src/index.ts for the server entry, env loading and startup gates.
 * NOT audited.
 */
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { getConnInfo } from "@hono/node-server/conninfo";
import { Hono } from "hono";
import type { Context, Next } from "hono";
import type { SigningRequest } from "@mandaterail/ac2-client";
import {
  isAc2BridgeAutoLocal,
  OPERATOR_TOKEN_HEADER,
  parseCorsOrigins,
  applyCorsHeaders,
  InsecureDevOperatorAuth,
  isTrustedLocalRequest,
  normalizeClientKey,
  isMainnetProfile,
  isOperatorAction,
  OPERATOR_ATTESTATION_HEADER,
  OperatorChallengeStore,
  RollingWindowRateLimiter,
  CHALLENGE_RATE_WINDOW_MS,
  CHALLENGE_STORE_MAX_ENTRIES,
  parseChallengeRateLimits,
  parseChallengeTtlMs,
  parseTrustedProxyHops,
  parseBridgeQueueLimits,
  parseOperatorAllowlist,
  resolveOperatorAttestationMode,
  SignedChallengeOperatorVerifier,
  type OperatorAction,
  InMemoryQueueStore,
  type ChallengeStore,
  type QueueItem,
  type QueueStore,
  type RateLimitStore,
  type StoreFactory,
  REQUESTER_ACTION,
  REQUESTER_AUTH_HEADER,
  RequesterKeyVerifier,
  parseRequesterAllowlist,
  pauseState,
  PAUSED_BODY,
} from "@mandaterail/core";
import algosdk from "algosdk";

/** Header carrying the per-request requester token (OA-N1). */
export const REQUESTER_TOKEN_HEADER = "x-mandaterail-requester-token";

export type PendingApproval = QueueItem<SigningRequest>;

/** Shared-state backends (Phase 2). Defaults: in-memory, single process. */
export interface BridgeStores {
  challenges?: ChallengeStore;
  challengeLimiter?: RateLimitStore;
  signLimiter?: RateLimitStore;
  queue?: QueueStore<SigningRequest>;
}

export interface BridgeAppOptions {
  /** Override socket remote address lookup (tests). */
  remoteAddress?: (c: Context) => string | undefined;
  /** Clock override (tests). */
  now?: () => number;
  /** Storage backends; omitted ones are in-memory. */
  stores?: BridgeStores;
  /** T6: shared backend (STATE_BACKEND); used for stores not given above. */
  backend?: StoreFactory;
}

const SUBJECT_ID_RE = /^[A-Za-z0-9-]{1,64}$/;
const PENDING_LIST_SUBJECT = "pending";

function sha256(s: string): Buffer {
  return createHash("sha256").update(s, "utf8").digest();
}

function localAccount(): algosdk.Account | null {
  const mn = process.env.ALGORAND_MNEMONIC;
  if (!mn) return null;
  return algosdk.mnemonicToSecretKey(mn.trim());
}

function signWithLocal(request: SigningRequest): {
  signature: string;
  publicKey: string;
  address: string;
} {
  const account = localAccount();
  if (!account) {
    throw new Error("AC2_BRIDGE_AUTO_LOCAL requires ALGORAND_MNEMONIC for local signing");
  }
  const bytes = request.message_b64
    ? Buffer.from(request.message_b64, "base64")
    : new TextEncoder().encode(request.message);
  const sig = algosdk.signBytes(bytes, account.sk);
  return {
    signature: Buffer.from(sig).toString("base64"),
    publicKey: Buffer.from(account.sk.slice(32)).toString("base64"),
    address: account.addr.toString(),
  };
}

const noStore = async (c: Context, next: Next) => {
  c.header("Cache-Control", "no-store");
  await next();
};

export function createBridgeApp(opts: BridgeAppOptions = {}) {
  const HOST = process.env.AC2_BRIDGE_HOST ?? "127.0.0.1";
  const autoLocalEnabled = () => isAc2BridgeAutoLocal();
  const clock = () => (opts.now ? opts.now() : Date.now());

  // OA-P2-I: bounded queue with TTL + retention eviction (clamped by the gate).
  const queue = parseBridgeQueueLimits() ?? {
    maxPending: 1000,
    pendingTtlMs: 900_000,
    retentionMs: 600_000,
    signRatePerMin: 60,
    signRatePerClient: 10,
    maxPendingPerClient: 50,
  };
  const be = opts.backend;
  const audience = process.env.OPERATOR_CHALLENGE_AUDIENCE ?? "mandaterail-ac2-bridge";
  if (be) {
    opts = { ...opts, stores: { ...opts.stores } };
    opts.stores!.queue ??= be.queue<SigningRequest>("ac2-bridge", queue);
    opts.stores!.challenges ??= be.challengeStore({
      audience,
      ttlMs: parseChallengeTtlMs() ?? 120_000,
      maxEntries: CHALLENGE_STORE_MAX_ENTRIES,
      now: opts.now,
    });
  }
  const memQueue = opts.stores?.queue ? undefined : new InMemoryQueueStore<SigningRequest>(queue);
  const queueStore: QueueStore<SigningRequest> = opts.stores?.queue ?? memQueue!;

  const socketAddress =
    opts.remoteAddress ??
    ((c: Context) => {
      try {
        return getConnInfo(c).remote.address;
      } catch {
        return undefined;
      }
    });

  // Startup gate already refused invalid modes / limits / MainNet token-lab.
  const ATTESTATION_MODE =
    resolveOperatorAttestationMode(isMainnetProfile()) ?? "signed-challenge";
  const challengeStore: ChallengeStore = opts.stores?.challenges ?? new OperatorChallengeStore({
    ttlMs: parseChallengeTtlMs() ?? 120_000,
    audience: process.env.OPERATOR_CHALLENGE_AUDIENCE ?? "mandaterail-ac2-bridge",
    maxEntries: CHALLENGE_STORE_MAX_ENTRIES,
    now: opts.now,
  });
  const signedVerifier = new SignedChallengeOperatorVerifier(
    challengeStore,
    parseOperatorAllowlist(),
    // P1-A: required by checkOperatorGate on MainNet / non-loopback bind;
    // when set, ARC-60 siwa.domain + rpIdHash are always enforced.
    { domain: process.env.OPERATOR_SIGNDATA_DOMAIN?.trim() || undefined },
  );

  // T8: allowlisted Ed25519 requester keys for POST /sign (nonces share the
  // challenge store, bound to action "request.sign" + requester address).
  const requesterAllowlist = parseRequesterAllowlist();
  const requesterVerifier = new RequesterKeyVerifier(challengeStore, requesterAllowlist);

  // OA-P2-G: rolling per-IP + global window, clamped limits (see core).
  const limits = parseChallengeRateLimits() ?? { perIp: 30, global: 600 };
  const proxyHops = parseTrustedProxyHops() ?? 0;
  if (be) {
    opts.stores!.signLimiter ??= be.rateLimiter({ name: "ac2-bridge:sign", windowMs: 60_000, perKey: queue.signRatePerClient, global: queue.signRatePerMin, now: opts.now });
    opts.stores!.challengeLimiter ??= be.rateLimiter({ name: "ac2-bridge:challenge", windowMs: CHALLENGE_RATE_WINDOW_MS, perKey: limits.perIp, global: limits.global, now: opts.now });
  }
  const signLimiter: RateLimitStore = opts.stores?.signLimiter ?? new RollingWindowRateLimiter({
    windowMs: 60_000,
    perKey: queue.signRatePerClient,
    global: queue.signRatePerMin,
    now: opts.now,
  });
  const challengeLimiter: RateLimitStore = opts.stores?.challengeLimiter ?? new RollingWindowRateLimiter({
    windowMs: CHALLENGE_RATE_WINDOW_MS,
    perKey: limits.perIp,
    global: limits.global,
    now: opts.now,
  });

  /**
   * Client key for rate limiting only. With AC2_BRIDGE_TRUSTED_PROXY_HOPS=n
   * (default 0 = off) take the n-th X-Forwarded-For entry from the right.
   * Never used for loopback / auth decisions.
   */
  /** OA-P1-O: the only localhost-trust decision in the bridge. */
  const isLocal = (c: Context) =>
    isTrustedLocalRequest({
      remoteAddress: socketAddress(c),
      header: (n) => c.req.header(n),
      trustedProxyHops: proxyHops,
    });

  function rateLimitKey(c: Context): string {
    const sock = normalizeClientKey(socketAddress(c));
    if (proxyHops <= 0) return sock;
    const xff = (c.req.header("X-Forwarded-For") ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    const fwd = xff[xff.length - proxyHops];
    return fwd ? normalizeClientKey(fwd) : sock;
  }

  async function authorizeOperatorAction(
    c: Context,
    action: OperatorAction,
    subjectId: string,
  ): Promise<{ ok: true } | { ok: false; status: 401 | 501; error: string; message: string }> {
    if (ATTESTATION_MODE === "signed-challenge") {
      const evidence = c.req.header(OPERATOR_ATTESTATION_HEADER);
      if (!evidence) {
        return {
          ok: false,
          status: 401,
          error: "attestation_required",
          message:
            "X-MandateRail-Operator-Attestation required (GET /operator/challenge, sign with an allowlisted Algorand account)",
        };
      }
      const r = await signedVerifier.verify(
        { kind: "signed-challenge", evidence },
        { action, subjectId, remoteAddress: socketAddress(c) },
      );
      if (!r.ok) return r;
      return { ok: true };
    }
    return InsecureDevOperatorAuth.authorize({
      headerToken: c.req.header(OPERATOR_TOKEN_HEADER),
      remoteAddress: socketAddress(c),
      isLocal: isLocal(c),
    });
  }

  function requireOperator(action: OperatorAction) {
    return async (c: Context, next: Next) => {
      const subject = action === "list" ? PENDING_LIST_SUBJECT : (c.req.param("id") ?? "");
      const auth = await authorizeOperatorAction(c, action, subject);
      if (!auth.ok) {
        return c.json({ error: auth.error, message: auth.message }, auth.status);
      }
      await next();
    };
  }

  const finalizeError = (
    c: Context,
    fin: { ok: false; error: "not_found" } | { ok: false; error: "not_pending"; status: string },
  ) =>
    fin.error === "not_found"
      ? c.json({ error: "not_found" }, 404)
      : c.json({ error: "not_pending", status: fin.status }, 409);

  const app = new Hono();
  const corsAllowlist = parseCorsOrigins();

  app.use("*", async (c, next) => {
    const origin = c.req.header("Origin");
    applyCorsHeaders((n, v) => c.header(n, v), origin, corsAllowlist);
    if (c.req.method === "OPTIONS") return c.body(null, 204);
    await next();
  });

  app.get("/health", (c) =>
    c.json({
      ok: true,
      service: "mandaterail-ac2-bridge",
      autoLocal: autoLocalEnabled(),
      paired: autoLocalEnabled() || Boolean(process.env.AC2_PAIRED === "true"),
      bind: HOST,
      operatorAttestationMode: ATTESTATION_MODE,
    }),
  );

  /**
   * Single-use, short-TTL operator challenge bound to action + subject.
   * Unauthenticated by design; rate-limited; no pending-id oracle (any
   * well-formed id gets a challenge, unknown ids 404 only after auth).
   */
  app.get("/operator/challenge", noStore, async (c) => {
    if (ATTESTATION_MODE !== "signed-challenge") {
      return c.json(
        { error: "signed_challenge_disabled", message: "OPERATOR_ATTESTATION_MODE is token-lab" },
        404,
      );
    }
    const action = c.req.query("action");
    const id = c.req.query("id") ?? "";
    if (!isOperatorAction(action)) {
      return c.json({ error: "invalid_action", message: "action must be approve|reject|list" }, 400);
    }
    // Only well-formed requests are counted by the limiter.
    if (action === "list" ? id !== PENDING_LIST_SUBJECT : !SUBJECT_ID_RE.test(id)) {
      return c.json({ error: "invalid_subject", message: "malformed subject id" }, 400);
    }
    if (!(await challengeLimiter.take(rateLimitKey(c)))) {
      c.header("Retry-After", String(Math.ceil(CHALLENGE_RATE_WINDOW_MS / 1000)));
      return c.json({ error: "rate_limited" }, 429);
    }
    try {
      const ch = await challengeStore.issue(action, id);
      return c.json({ ...ch, header: "X-MandateRail-Operator-Attestation" });
    } catch {
      return c.json({ error: "challenge_unavailable" }, 503);
    }
  });

  /**
   * T8: requester nonce for POST /sign. Issued for any well-formed address
   * (no allowlist oracle); rate-limited like operator challenges.
   */
  app.get("/requester/challenge", noStore, async (c) => {
    if (requesterAllowlist.length === 0) {
      return c.json({ error: "requester_auth_disabled", message: "REQUESTER_ALLOWLIST is empty" }, 404);
    }
    const address = c.req.query("address") ?? "";
    if (!algosdk.isValidAddress(address)) {
      return c.json({ error: "invalid_subject", message: "address must be an Algorand address" }, 400);
    }
    if (!(await challengeLimiter.take(rateLimitKey(c)))) {
      c.header("Retry-After", String(Math.ceil(CHALLENGE_RATE_WINDOW_MS / 1000)));
      return c.json({ error: "rate_limited" }, 429);
    }
    try {
      const ch = await challengeStore.issue(REQUESTER_ACTION, address);
      return c.json({
        nonce: ch.nonce,
        audience: ch.audience,
        address,
        issuedAt: ch.issuedAt,
        expiresAt: ch.expiresAt,
        header: "X-MandateRail-Requester-Auth",
        sign: "algosdk.signBytes(canonical request: method POST, path /sign, sha256 of exact body, nonce, ISO timestamp)",
      });
    } catch {
      return c.json({ error: "challenge_unavailable" }, 503);
    }
  });

  const pairStatus = () => {
    const auto = autoLocalEnabled();
    const pairedFlag = process.env.AC2_PAIRED === "true";
    return {
      paired: auto || pairedFlag,
      mode: auto ? "auto-local" : pairedFlag ? "manual" : "unpaired",
    };
  };
  app.post("/pair/status", async (c) => {
    return c.json({
      ...pairStatus(),
      pendingCount: await queueStore.countPending(clock()),
    });
  });
  app.get("/pair/status", (c) => c.json(pairStatus()));

  app.post("/sign", noStore, async (c) => {
    // P2-T10 kill switch
    const ps = pauseState();
    if (ps.paused) return c.json({ ...PAUSED_BODY, reason: ps.reason }, 503);
    // T8-P3-1: keep the exact received bytes for the requester-signature hash.
    const rawBody = new Uint8Array(await c.req.arrayBuffer().catch(() => new ArrayBuffer(0)));
    let body: SigningRequest | null = null;
    try {
      body = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(rawBody)) as SigningRequest | null;
    } catch {
      body = null;
    }
    if (!body || typeof body !== "object" || !body.message) {
      return c.json({ error: "invalid_signing_request" }, 400);
    }
    let clientKey = rateLimitKey(c);
    const requesterHeader = c.req.header(REQUESTER_AUTH_HEADER);
    const rateLimited = () => {
      c.header("Retry-After", "60");
      return c.json({ error: "rate_limited" }, 429);
    };

    // Auto-local CI path (already gated to TestNet lab by insecure-dev).
    if (autoLocalEnabled()) {
      // OA-P2-R: auto-sign only for trusted local callers (no proxy headers / hops).
      if (!isLocal(c)) {
        return c.json(
          { error: "forbidden", message: "auto-local signing is only available to direct loopback callers" },
          403,
        );
      }
      if (!(await signLimiter.take(clientKey))) return rateLimited();
      try {
        return c.json(signWithLocal(body));
      } catch (e) {
        return c.json(
          { error: "auto_local_failed", message: e instanceof Error ? e.message : String(e) },
          500,
        );
      }
    }

    if (requesterHeader !== undefined) {
      // T8: allowlisted requester key (any network, any source address).
      const r = await requesterVerifier.verify({
        header: requesterHeader,
        method: "POST",
        path: "/sign",
        body: rawBody,
        nowMs: clock(),
      });
      if (!r.ok) return c.json({ error: r.error, message: r.message }, r.status);
      clientKey = `requester:${r.address}`;
    } else if (isMainnetProfile()) {
      // MainNet: no loopback trust for /sign.
      return c.json(
        { error: "requester_auth_required", message: "X-MandateRail-Requester-Auth required (GET /requester/challenge)" },
        401,
      );
    } else if (ATTESTATION_MODE === "signed-challenge") {
      // TestNet (unchanged until T9): agents are co-located — queue from
      // loopback only (queueing grants nothing; approval needs an operator).
      if (!isLocal(c)) {
        return c.json(
          { error: "unauthorized", message: "POST /sign queue is loopback-only (no proxy/forwarded headers) in signed-challenge mode" },
          401,
        );
      }
    } else {
      const auth = InsecureDevOperatorAuth.authorize({
        headerToken: c.req.header(OPERATOR_TOKEN_HEADER),
        remoteAddress: socketAddress(c),
        isLocal: isLocal(c),
      });
      if (!auth.ok) {
        return c.json({ error: auth.error, message: auth.message }, auth.status);
      }
    }

    // OA-P2-M: rate limit only callers that passed the loopback/auth gate.
    if (!(await signLimiter.take(clientKey))) return rateLimited();
    const id = crypto.randomUUID();
    // OA-N1: high-entropy requester token, returned once; only its hash is kept.
    const requesterToken = randomBytes(32).toString("base64url");
    const nowMs = clock();
    const slot = await queueStore.insert(
      {
        id,
        status: "pending",
        createdAt: new Date(nowMs).toISOString(),
        createdMs: nowMs,
        request: body,
        clientKey,
        requesterTokenHash: sha256(requesterToken),
      },
      nowMs,
    );
    if (slot === "client_pending_cap") {
      c.header("Retry-After", "60");
      return c.json({ error: "client_pending_cap", message: "AC2_BRIDGE_MAX_PENDING_PER_CLIENT reached" }, 429);
    }
    if (slot === "queue_full") {
      c.header("Retry-After", "60");
      return c.json({ error: "queue_full", message: "AC2_BRIDGE_MAX_PENDING reached (uncollected results are kept)" }, 503);
    }
    return c.json(
      {
        id,
        status: "pending",
        requesterToken,
        statusUrl: `/requests/${id}/status`,
      },
      202,
    );
  });

  /**
   * OA-N1: requester-scoped status for one queued request.
   * Auth: X-MandateRail-Requester-Token (constant-time compare of sha256), or
   * loopback in TestNet token-lab. Unknown id and wrong token are the same 404.
   */
  app.get("/requests/:id/status", noStore, async (c) => {
    const id = c.req.param("id") ?? "";
    const item = await queueStore.get(id, clock());
    const token = c.req.header(REQUESTER_TOKEN_HEADER);
    let authorized = false;
    if (token) {
      const got = sha256(token);
      const want = item?.requesterTokenHash ?? sha256(`__absent__:${randomBytes(16).toString("hex")}`);
      authorized = timingSafeEqual(got, want) && !!item;
    } else if (
      ATTESTATION_MODE === "token-lab" &&
      !isMainnetProfile() &&
      isLocal(c)
    ) {
      authorized = !!item;
    } else {
      return c.json(
        { error: "requester_token_required", message: "X-MandateRail-Requester-Token required" },
        401,
      );
    }
    if (!authorized || !item) return c.json({ error: "not_found" }, 404);
    // OA-P2-N: the requester has now seen the final state -> evictable.
    if (item.status !== "pending") await queueStore.markCollected(id);
    if (item.status === "approved") {
      return c.json({
        id,
        status: item.status,
        signature: item.signature,
        publicKey: item.publicKey,
        address: item.address,
      });
    }
    return c.json({ id, status: item.status });
  });

  app.get("/pending", noStore, requireOperator("list"), async (c) => {
    const list = (await queueStore.list(clock())).map((p) => ({
      id: p.id,
      status: p.status,
      createdAt: p.createdAt,
      mandateId: p.request.mandateId,
      sig_hint: p.request.sig_hint,
      display_hint: p.request.display_hint,
      message: p.request.message,
      signature: p.signature,
      publicKey: p.publicKey,
      address: p.address,
    }));
    return c.json({ pending: list });
  });

  app.post("/approve/:id", noStore, requireOperator("approve"), async (c) => {
    const id = c.req.param("id") as string;
    const item = await queueStore.get(id, clock());
    if (!item) return c.json({ error: "not_found" }, 404);
    // P2-C: terminal states are immutable.
    if (item.status !== "pending") {
      return c.json({ error: "not_pending", status: item.status }, 409);
    }
    const body = (await c.req.json().catch(() => null)) as {
      signature?: string;
      publicKey?: string;
      address?: string;
      useLocal?: boolean;
    } | null;

    // P2-D: local-mnemonic signing only in TestNet auto-local lab mode.
    if (body?.useLocal && !autoLocalEnabled()) {
      return c.json(
        { error: "use_local_disabled", message: "useLocal requires AC2_BRIDGE_AUTO_LOCAL (TestNet lab only)" },
        400,
      );
    }
    if (autoLocalEnabled() && (body?.useLocal || !body?.signature)) {
      try {
        const result = signWithLocal(item.request);
        const fin = await queueStore.finalize(id, "approved", result, clock());
        if (!fin.ok) return finalizeError(c, fin);
        return c.json({ id, status: "approved", ...result });
      } catch (e) {
        return c.json(
          { error: "approve_local_failed", message: e instanceof Error ? e.message : String(e) },
          500,
        );
      }
    }
    if (!body?.signature) return c.json({ error: "signature_required" }, 400);

    // Compare-and-set: a concurrent approve/reject in another process loses here.
    const fin = await queueStore.finalize(
      id,
      "approved",
      { signature: body.signature, publicKey: body.publicKey, address: body.address },
      clock(),
    );
    if (!fin.ok) return finalizeError(c, fin);
    return c.json({
      id,
      status: "approved",
      signature: fin.item.signature,
      publicKey: fin.item.publicKey,
      address: fin.item.address,
    });
  });

  app.post("/reject/:id", noStore, requireOperator("reject"), async (c) => {
    const id = c.req.param("id") as string;
    const fin = await queueStore.finalize(id, "rejected", {}, clock());
    if (!fin.ok) return finalizeError(c, fin);
    return c.json({ id, status: "rejected" });
  });

  return {
    app,
    /** In-memory queue map (empty Map when an external queue store is used). */
    pending: memQueue?.items ?? new Map<string, PendingApproval>(),
    queueStore,
    challengeStore,
    mode: ATTESTATION_MODE,
  };
}

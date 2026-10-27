/**
 * MandateRail console mandate store — Hono app (testable; no listen / gates).
 *
 * Auth (NOT audited):
 *  - signed-challenge (OPERATOR_ATTESTATION_MODE=signed-challenge, required for
 *    any non-loopback bind or proxy): every /mandates route needs
 *    X-MandateRail-Operator-Attestation over a single-use GET
 *    /operator/challenge nonce bound to (action, id), signed by an
 *    OPERATOR_ALLOWLIST account; ARC-60 evidence must match
 *    OPERATOR_SIGNDATA_DOMAIN. Audience is separate from the ac2-bridge
 *    (CONSOLE_CHALLENGE_AUDIENCE, default mandaterail-console), so bridge
 *    challenges cannot be replayed here.
 *  - otherwise (local dev store): /mandates routes are allowed only for
 *    isTrustedLocalRequest callers (direct loopback, no proxy headers, hops 0).
 *
 * Unsigned / stub-signed mandates stay unsigned-draft and are never authorized
 * for execute; the console does not replace the AC2 human gate.
 */
import { randomUUID } from "node:crypto";
import { getConnInfo } from "@hono/node-server/conninfo";
import { Hono } from "hono";
import type { Context, Next } from "hono";
import { bodyLimit } from "hono/body-limit";
import { IntentMandateSchema } from "@mandaterail/schema";
import {
  applyCorsHeaders,
  canonicalMandateBytes,
  CHALLENGE_RATE_WINDOW_MS,
  CHALLENGE_STORE_MAX_ENTRIES,
  evaluateMandate,
  isConsoleOperatorAction,
  isMainnetProfile,
  isTrustedLocalRequest,
  normalizeClientKey,
  OPERATOR_ATTESTATION_HEADER,
  OperatorChallengeStore,
  parseChallengeTtlMs,
  parseConsoleLimits,
  parseCorsOrigins,
  parseOperatorAllowlist,
  parseTrustedProxyHops,
  resolveOperatorAttestationMode,
  RollingWindowRateLimiter,
  SignedChallengeOperatorVerifier,
  verifyAc2Signature,
  type ConsoleOperatorAction,
  type ChallengeStore,
  type MandateStore,
  type RateLimitStore,
  type StoreFactory,
} from "@mandaterail/core";
import {
  FileMandateStore,
  classifyMandateAuth,
  StoreFullError,
  parseStrictIsoUtc,
  STUB_SIGNATURE_PREFIX,
} from "./store.js";

/** Subject for mandate.list. */
export const MANDATE_LIST_SUBJECT = "mandates";
/** Mandate ids accepted for challenges / signed-challenge create. */
const MANDATE_ID_RE = /^[A-Za-z0-9._:-]{1,128}$/;

/** Shared-state backends (Phase 2). Defaults: in-memory / JSON file. */
export interface ConsoleStores {
  challenges?: ChallengeStore;
  limiter?: RateLimitStore;
  mandates?: MandateStore;
}

export interface ConsoleAppOptions {
  remoteAddress?: (c: Context) => string | undefined;
  now?: () => number;
  stores?: ConsoleStores;
  /** T6: shared backend (STATE_BACKEND); used for stores not given above. */
  backend?: StoreFactory;
}

const noStore = async (c: Context, next: Next) => {
  c.header("Cache-Control", "no-store");
  await next();
};

/** Signed createdAt may be at most this far in the past / future. */
export const CREATED_AT_MAX_PAST_MS = 15 * 60 * 1000;
export const CREATED_AT_MAX_FUTURE_MS = 2 * 60 * 1000;
const ISO_RE =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;

/** null when ok, else a reason. */
export function checkCreatedAt(value: string, nowMs: number): string | null {
  if (!ISO_RE.test(value)) return "createdAt must be an ISO 8601 timestamp";
  const t = Date.parse(value);
  if (!Number.isFinite(t)) return "createdAt is not a valid date";
  if (t < nowMs - CREATED_AT_MAX_PAST_MS) return "createdAt is too far in the past";
  if (t > nowMs + CREATED_AT_MAX_FUTURE_MS) return "createdAt is in the future";
  return null;
}

export function createConsoleApp(opts: ConsoleAppOptions = {}) {
  const socketAddress =
    opts.remoteAddress ??
    ((c: Context) => {
      try {
        return getConnInfo(c).remote.address;
      } catch {
        return undefined;
      }
    });
  const MODE =
    resolveOperatorAttestationMode(isMainnetProfile()) ?? "signed-challenge";
  const signed = MODE === "signed-challenge";
  const limits = parseConsoleLimits() ?? {
    ratePerIp: 30,
    rateGlobal: 300,
    maxBodyBytes: 16_384,
    maxMandates: 1000,
  };
  const proxyHops = parseTrustedProxyHops() ?? 0;

  const be = opts.backend;
  const mandates: MandateStore = opts.stores?.mandates ?? be?.mandates("console") ?? new FileMandateStore();
  const consoleAudience = process.env.CONSOLE_CHALLENGE_AUDIENCE ?? "mandaterail-console";
  const challengeStore: ChallengeStore = opts.stores?.challenges ?? be?.challengeStore({
    audience: consoleAudience,
    ttlMs: parseChallengeTtlMs() ?? 120_000,
    maxEntries: CHALLENGE_STORE_MAX_ENTRIES,
    now: opts.now,
  }) ?? new OperatorChallengeStore({
    ttlMs: parseChallengeTtlMs() ?? 120_000,
    audience: process.env.CONSOLE_CHALLENGE_AUDIENCE ?? "mandaterail-console",
    maxEntries: CHALLENGE_STORE_MAX_ENTRIES,
    now: opts.now,
  });
  const verifier = new SignedChallengeOperatorVerifier(
    challengeStore,
    parseOperatorAllowlist(),
    { domain: process.env.OPERATOR_SIGNDATA_DOMAIN?.trim() || undefined },
  );
  const limiter: RateLimitStore = opts.stores?.limiter ?? be?.rateLimiter({
    name: "console:operator",
    windowMs: CHALLENGE_RATE_WINDOW_MS,
    perKey: limits.ratePerIp,
    global: limits.rateGlobal,
    now: opts.now,
  }) ?? new RollingWindowRateLimiter({
    windowMs: CHALLENGE_RATE_WINDOW_MS,
    perKey: limits.ratePerIp,
    global: limits.rateGlobal,
    now: opts.now,
  });

  const isLocal = (c: Context) =>
    isTrustedLocalRequest({
      remoteAddress: socketAddress(c),
      header: (n) => c.req.header(n),
      trustedProxyHops: proxyHops,
    });

  function clientKey(c: Context): string {
    const sock = normalizeClientKey(socketAddress(c));
    if (proxyHops <= 0) return sock;
    const xff = (c.req.header("X-Forwarded-For") ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    const fwd = xff[xff.length - proxyHops];
    return fwd ? normalizeClientKey(fwd) : sock;
  }

  const rateLimit = async (c: Context, next: Next) => {
    if (!(await limiter.take(clientKey(c)))) {
      c.header(
        "Retry-After",
        String(Math.ceil(CHALLENGE_RATE_WINDOW_MS / 1000)),
      );
      return c.json({ error: "rate_limited" }, 429);
    }
    await next();
  };

  /** Operator auth for one console action + subject. */
  async function authorize(
    c: Context,
    action: ConsoleOperatorAction,
    subjectId: string,
  ): Promise<Response | null> {
    if (!signed) {
      if (isLocal(c)) return null;
      return c.json(
        {
          error: "unauthorized",
          message:
            "console store is local-only (direct loopback, no proxy) unless OPERATOR_ATTESTATION_MODE=signed-challenge",
        },
        401,
      );
    }
    const evidence = c.req.header(OPERATOR_ATTESTATION_HEADER);
    if (!evidence) {
      return c.json(
        {
          error: "attestation_required",
          message:
            "X-MandateRail-Operator-Attestation required (GET /operator/challenge, sign with an allowlisted Algorand account)",
        },
        401,
      );
    }
    const r = await verifier.verify(
      { kind: "signed-challenge", evidence },
      { action, subjectId, remoteAddress: socketAddress(c) },
    );
    if (!r.ok) return c.json({ error: r.error, message: r.message }, r.status);
    return null;
  }

  const app = new Hono();
  const corsAllowlist = parseCorsOrigins();

  app.use("*", async (c, next) => {
    applyCorsHeaders(
      (n, v) => c.header(n, v),
      c.req.header("Origin"),
      corsAllowlist,
    );
    if (c.req.method === "OPTIONS") return c.body(null, 204);
    await next();
  });
  app.use(
    "*",
    bodyLimit({
      maxSize: limits.maxBodyBytes,
      onError: (c) =>
        c.json(
          { error: "payload_too_large", maxBytes: limits.maxBodyBytes },
          413,
        ),
    }),
  );

  app.get("/health", (c) =>
    c.json({
      ok: true,
      service: "mandaterail-console",
      operatorAttestationMode: signed ? "signed-challenge" : "local-only",
      note: "unsigned-draft records are not authorized for execute",
    }),
  );

  app.get("/", (c) =>
    c.json({
      name: "MandateRail console (mandate store)",
      warning:
        "Unsigned / stub-signed mandates are unsigned-draft only — not authorized spend. Use AC2 bridge human approve before any execute path.",
      auth: signed
        ? "signed-challenge OperatorAttestation"
        : "local-only (loopback)",
      endpoints: [
        "GET /operator/challenge?action=mandate.create|mandate.revoke|mandate.read|mandate.list&id=",
        "GET /mandates",
        "POST /mandates",
        "GET /mandates/:id",
        "POST /mandates/:id/revoke",
        "POST /mandates/:id/authorize-check",
      ],
    }),
  );

  app.get("/operator/challenge", noStore, async (c) => {
    if (!signed) {
      return c.json(
        {
          error: "signed_challenge_disabled",
          message: "console is in local-only mode",
        },
        404,
      );
    }
    const action = c.req.query("action");
    const id = c.req.query("id") ?? "";
    if (!isConsoleOperatorAction(action)) {
      return c.json(
        {
          error: "invalid_action",
          message:
            "action must be mandate.create|mandate.revoke|mandate.read|mandate.list",
        },
        400,
      );
    }
    if (
      action === "mandate.list"
        ? id !== MANDATE_LIST_SUBJECT
        : !MANDATE_ID_RE.test(id)
    ) {
      return c.json(
        { error: "invalid_subject", message: "malformed subject id" },
        400,
      );
    }
    if (!(await limiter.take(clientKey(c)))) {
      c.header(
        "Retry-After",
        String(Math.ceil(CHALLENGE_RATE_WINDOW_MS / 1000)),
      );
      return c.json({ error: "rate_limited" }, 429);
    }
    try {
      return c.json({
        ...(await challengeStore.issue(action, id)),
        header: "X-MandateRail-Operator-Attestation",
      });
    } catch {
      return c.json({ error: "challenge_unavailable" }, 503);
    }
  });

  // Hono "/mandates/*" also matches "/mandates" (one count per request).
  app.use("/mandates/*", noStore, rateLimit);

  app.get("/mandates", async (c) => {
    const denied = await authorize(c, "mandate.list", MANDATE_LIST_SUBJECT);
    if (denied) return denied;
    const items = await mandates.list();
    return c.json({
      items: items.map((r) => ({
        ...r.mandate,
        authorization: classifyMandateAuth(r.mandate, r.server),
      })),
    });
  });

  app.get("/mandates/:id", async (c) => {
    const id = c.req.param("id");
    const denied = await authorize(c, "mandate.read", id);
    if (denied) return denied;
    const r = await mandates.get(id);
    if (!r) return c.json({ error: "not_found" }, 404);
    return c.json({
      ...r.mandate,
      authorization: classifyMandateAuth(r.mandate, r.server),
    });
  });

  app.post("/mandates", async (c) => {
    const body = await c.req.json().catch(() => null);
    if (!body || typeof body !== "object") {
      return c.json({ error: "invalid_json" }, 400);
    }
    const bodyId = (body as { id?: unknown }).id;
    if (
      bodyId !== undefined &&
      bodyId !== null &&
      (typeof bodyId !== "string" || !MANDATE_ID_RE.test(bodyId))
    ) {
      return c.json({ error: "invalid_id" }, 400);
    }
    if (signed && typeof bodyId !== "string") {
      return c.json(
        {
          error: "id_required",
          message:
            "signed-challenge create requires a client-chosen mandate id (the challenge subject)",
        },
        400,
      );
    }
    const denied = await authorize(
      c,
      "mandate.create",
      typeof bodyId === "string" ? bodyId : "new",
    );
    if (denied) return denied;

    const now = new Date(opts.now?.() ?? Date.now());
    const later = new Date(now.getTime() + 24 * 60 * 60 * 1000);
    const rawSig = (body as { signature?: string | null }).signature;
    const hasRealSig =
      typeof rawSig === "string" &&
      rawSig.length > 0 &&
      !rawSig.startsWith(STUB_SIGNATURE_PREFIX);

    // Signed create: the client signature covers canonicalMandateBytes of the
    // exact body. The console adds no defaults, createdAt or metadata, and
    // rejects the create if schema parsing would change any signed byte.
    if ((body as { revoked?: unknown }).revoked === true) {
      return c.json(
        { error: "already_revoked", message: "cannot create a revoked mandate" },
        400,
      );
    }

    if (hasRealSig) {
      const raw = body as Record<string, unknown>;
      if (typeof raw.createdAt === "string") {
        const skew = checkCreatedAt(raw.createdAt, now.getTime());
        if (skew) return c.json({ error: "invalid_createdAt", message: skew }, 400);
      }
      if (typeof raw.createdAt !== "string") {
        return c.json(
          {
            error: "signed_create_requires_createdAt",
            message:
              "signed creates must include createdAt (it is part of the signed bytes)",
          },
          400,
        );
      }
      const signedParsed = IntentMandateSchema.safeParse(raw);
      if (!signedParsed.success) {
        return c.json(
          { error: "invalid_mandate", details: signedParsed.error.format() },
          400,
        );
      }
      const before = Buffer.from(canonicalMandateBytes(raw));
      const after = Buffer.from(canonicalMandateBytes(signedParsed.data));
      if (!before.equals(after)) {
        return c.json(
          {
            error: "signed_fields_changed",
            message:
              "the stored mandate would differ from the signed bytes; send the full canonical mandate",
          },
          400,
        );
      }
      const v = await verifyAc2Signature({
        mandate: signedParsed.data,
        principal: signedParsed.data.principal,
        signature: signedParsed.data.signature,
      });
      if (!v.ok) {
        return c.json(
          { error: "invalid_signature", message: "AC2 signature did not verify" },
          400,
        );
      }
      try {
        const created = await mandates.create(signedParsed.data, {
          maxMandates: limits.maxMandates,
          signatureVerified: true,
        });
        return c.json(
          {
            ...created.mandate,
            authorization: {
              status: "signature-verified",
              authorizedForExecute: true,
              message:
                "ed25519 signature verified at create; stored bytes unchanged",
            },
          },
          201,
        );
      } catch (e) {
        if (e instanceof StoreFullError) {
          return c.json({ error: "store_full", message: e.message }, 503);
        }
        console.error("[console] create_failed", e);
        return c.json(
          { error: "create_failed", message: "mandate could not be created" },
          409,
        );
      }
    }

    // Unsigned draft: server fills defaults and its own metadata (nothing is signed).
    const candidate = {
      // local-only create without an id gets a server-generated UUID
      id: typeof bodyId === "string" ? bodyId : randomUUID(),
      principal:
        (body as { principal?: string }).principal ?? "did:example:alice",
      agent: (body as { agent?: string }).agent ?? "did:example:agent-1",
      maxAmount: (body as { maxAmount?: string }).maxAmount ?? "10.00",
      asset: (body as { asset?: string }).asset ?? "USDC",
      allowlist: (body as { allowlist?: string[] }).allowlist ?? [
        "demo-merchant",
      ],
      expiresAt:
        (body as { expiresAt?: string }).expiresAt ?? later.toISOString(),
      revoked: false,
      nonce: (body as { nonce?: string }).nonce ?? randomUUID(),
      signature: null,
      principalPubkey: (body as { principalPubkey?: string }).principalPubkey,
      createdAt: now.toISOString(),
      metadata: {
        ...((body as { metadata?: Record<string, unknown> }).metadata ?? {}),
        draftStatus: "unsigned-draft",
        consoleNote:
          "Console file-store does not replace AC2 human approval. Execute paths refuse unsigned-draft.",
      },
    };

    // R31-P3-5: expiresAt must be strict ISO 8601 UTC with a trailing Z.
    if (parseStrictIsoUtc(candidate.expiresAt) === null) {
      return c.json({ error: "invalid_mandate", details: "expiresAt must be ISO 8601 UTC with a trailing Z (YYYY-MM-DDTHH:MM:SS[.sss]Z)" }, 400);
    }
    const parsed = IntentMandateSchema.safeParse(candidate);
    if (!parsed.success) {
      return c.json(
        { error: "invalid_mandate", details: parsed.error.format() },
        400,
      );
    }
    const authorization = classifyMandateAuth(parsed.data);

    try {
      const created = await mandates.create(parsed.data, {
        maxMandates: limits.maxMandates,
      });
      return c.json({ ...created.mandate, authorization }, 201);
    } catch (e) {
      if (e instanceof StoreFullError) {
        return c.json({ error: "store_full", message: e.message }, 503);
      }
      // Details stay server-side; clients get a generic error.
      console.error("[console] create_failed", e);
      return c.json(
        { error: "create_failed", message: "mandate could not be created" },
        409,
      );
    }
  });

  app.post("/mandates/:id/revoke", async (c) => {
    const id = c.req.param("id");
    const denied = await authorize(c, "mandate.revoke", id);
    if (denied) return denied;
    const r = await mandates.revoke(id);
    if (!r) return c.json({ error: "not_found" }, 404);
    return c.json({
      ...r.mandate,
      authorization: classifyMandateAuth(r.mandate, r.server),
    });
  });

  /**
   * Explicit authorize/execute check — same policy path as merchant middleware.
   * Requires mandate.read auth. Refuses unsigned-draft / invalid signatures.
   */
  app.post("/mandates/:id/authorize-check", async (c) => {
    const id = c.req.param("id");
    const denied = await authorize(c, "mandate.read", id);
    if (denied) return denied;
    const rec = await mandates.get(id);
    if (!rec) return c.json({ error: "not_found" }, 404);
    const m = rec.mandate;

    const body = (await c.req.json().catch(() => ({}))) as {
      merchantId?: string;
      amount?: string;
      asset?: string;
    };

    let classification = classifyMandateAuth(m, rec.server);

    // Unsigned / stub never proceed — console must not bypass AC2 human gate.
    if (
      classification.status === "unsigned-draft" ||
      classification.status === "stub-signature" ||
      classification.status === "revoked" ||
      classification.status === "expired" ||
      classification.status === "signature-invalid"
    ) {
      return c.json(
        {
          ok: false,
          error: "unsigned_or_unverified",
          authorization: classification,
          message:
            "Console refuses to treat unsigned-draft / stub / invalid mandates as authorized for execute. Complete AC2 human approve and store a verified signature.",
        },
        403,
      );
    }

    // signature-present-unverified or signature-verified: run full policy (includes verify).
    const result = await evaluateMandate(m, {
      merchantId: body.merchantId ?? m.allowlist[0] ?? "demo-merchant",
      amount: body.amount ?? m.maxAmount,
      asset: body.asset ?? m.asset,
      allowUnsigned: false,
    });

    if (result.ok) {
      classification = {
        status: "signature-verified",
        authorizedForExecute: true,
        message: "ed25519 signature verified via evaluateMandate",
      };
    }

    if (!result.ok) {
      return c.json(
        {
          ok: false,
          error: result.reason,
          message: result.message,
          authorization: classification,
        },
        403,
      );
    }

    return c.json({
      ok: true,
      authorization: classification,
      mandateId: m.id,
      note: "Policy ok — still not a settlement. Merchant middleware + facilitator required.",
    });
  });

  return {
    app,
    mode: signed ? "signed-challenge" : "local-only",
    limits,
    stores: { mandates, challenges: challengeStore, limiter },
  };
}

import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";

function loadDotEnv() {
  for (const p of [
    resolve(process.cwd(), ".env"),
    resolve(process.cwd(), "../../.env"),
    resolve(process.cwd(), "../../../.env"),
  ]) {
    if (!existsSync(p)) continue;
    for (const line of readFileSync(p, "utf8").split(/\r?\n/)) {
      const t = line.trim();
      if (!t || t.startsWith("#")) continue;
      const i = t.indexOf("=");
      if (i <= 0) continue;
      const key = t.slice(0, i).trim();
      let val = t.slice(i + 1).trim();
      if (
        (val.startsWith('"') && val.endsWith('"')) ||
        (val.startsWith("'") && val.endsWith("'"))
      )
        val = val.slice(1, -1);
      if (process.env[key] === undefined) process.env[key] = val;
    }
    break;
  }
}
loadDotEnv();

import { serve } from "@hono/node-server";
import { getConnInfo } from "@hono/node-server/conninfo";
import { DemoMandateStore, demoMandateLimitsFromEnv, demoWriteMode, mountDemoMandates } from "./demo-mandates.js";
import { Hono } from "hono";
import {
  mandateRail,
  paymentRequiredBody,
  GOPLAUSIBLE_FEE_PAYER,
} from "@mandaterail/middleware-hono";
import type { IntentMandate } from "@mandaterail/schema";
import {
  createGoPlausibleClient,
  type PaymentRequirements,
} from "@mandaterail/facilitator-goplausible";
import { loadStateEnvFile, openStateBackendOrExit } from "@mandaterail/storage";
import { assertMainnetEnvGateOrExit, pauseState, PAUSED_BODY } from "@mandaterail/core";
import {
  setReceiptStore,
  getReceiptStore,
  type Receipt,
  extractTxId,
  getReceipt,
  listReceipts,
  persistReceipt,
  receiptsPath,
} from "./receipts.js";
import {
  assertInsecureDevOrExit,
  assertOperatorGateOrExit,
  parseCorsOrigins,
  applyCorsHeaders,
  validateMerchantApiKeyPrefix,
  API_KEY_HEADER,
  isLoopbackHost,
  networkProfile,
  algodCheckRequired,
  verifyAlgodMatchesProfile,
  InMemorySpendStore,
  toMicro,
  type SpendStore,
} from "@mandaterail/core";

assertInsecureDevOrExit("demo-api");
assertOperatorGateOrExit("demo-api");
// T6: MainNet env gate (after the state env file is loaded; names only, never values).
try {
  loadStateEnvFile("demo-api");
} catch {
  // reported (redacted) by openStateBackendOrExit below
}
assertMainnetEnvGateOrExit("demo-api", { requireFeePayer: true });

type DemoVars = {
  Variables: {
    mandate: IntentMandate;
    facilitatorSettle: unknown;
    paymentRequirements: PaymentRequirements;
  };
};

const PORT = Number(process.env.DEMO_API_PORT ?? 8787);
/** Default MUST stay loopback — block non-localhost exposure without auth. */
const HOST = process.env.DEMO_API_HOST ?? "127.0.0.1";

/** Receive-only payTo — distinct from the payer wallet (ALGORAND_MNEMONIC). */
const MERCHANT_ADDRESS = process.env.MERCHANT_ADDRESS ?? "";
const PRICE_HUMAN = process.env.PRICE_USDC ?? "0.01";
// T5: chain + USDC ASA from one profile (MainNet USDC 31566704; throws on
// ambiguous config). MainNet has no default fee payer.
const PROFILE = (() => {
  try {
    return networkProfile();
  } catch (e) {
    console.error(`[demo-api] REFUSING TO START: ${e instanceof Error ? e.message : e}`);
    process.exit(1);
  }
})();
// T5-P3: algod must serve this chain and the USDC ASA must have 6 decimals.
if (algodCheckRequired(PROFILE)) {
  try {
    await verifyAlgodMatchesProfile(PROFILE, { algodUrl: process.env.ALGOD_URL, token: process.env.ALGOD_TOKEN });
  } catch (e) {
    console.error(`[demo-api] REFUSING TO START: ${e instanceof Error ? e.message : "algod check failed"}`);
    process.exit(1);
  }
}
// T6: STATE_BACKEND (from /etc/mandaterail/state-demo-api.env or env).
const backend = await openStateBackendOrExit("demo-api");
let spendStore: SpendStore;
if (backend) {
  setReceiptStore(backend.receipts<Receipt>("demo-api"));
  spendStore = backend.spend("demo-api");
} else {
  // memory: seed today's settled spend from the receipts file so a restart
  // doesn't reset the daily cap.
  const mem = new InMemorySpendStore();
  for (const r of await getReceiptStore().list(10_000)) {
    try {
      mem.recordSettled({ id: `receipt:${r.receiptId}`, payer: r.payer, amountMicro: toMicro(r.amount), createdMs: Date.parse(r.createdAt), txId: r.txId });
    } catch {
      /* skip malformed legacy rows */
    }
  }
  spendStore = mem;
}
const NETWORK = PROFILE.caip2;
const USDC_ASA = PROFILE.usdcAsaId;
const FEE_PAYER = process.env.FEE_PAYER ?? (PROFILE.isMainnet ? "" : GOPLAUSIBLE_FEE_PAYER);

const demoStore = new DemoMandateStore(demoMandateLimitsFromEnv());

function seed() {
  const now = new Date();
  const later = new Date(now.getTime() + 24 * 60 * 60 * 1000);
  const m: IntentMandate = {
    id: "demo-mandate-1",
    principal: "PLACEHOLDER_ALGORAND_ADDRESS",
    agent: "did:example:agent-1",
    maxAmount: "1.00",
    asset: "USDC",
    allowlist: ["demo-merchant"],
    expiresAt: later.toISOString(),
    revoked: false,
    nonce: "demo-nonce-1",
    signature: null,
    createdAt: now.toISOString(),
    metadata: {
      note: "unsigned seed — POST a signed mandate to /demo/mandates for paid path",
    },
  };
  demoStore.pin(m);
}
seed();

const app = new Hono<DemoVars>();

const corsAllowlist = parseCorsOrigins();

app.use("*", async (c, next) => {
  const origin = c.req.header("Origin");
  if (c.req.method === "OPTIONS") {
    const applied = applyCorsHeaders((n, v) => c.header(n, v), origin, corsAllowlist);
    if (!applied) return c.body(null, 204);
    return c.body(null, 204);
  }
  applyCorsHeaders((n, v) => c.header(n, v), origin, corsAllowlist);
  await next();
});

app.use("*", async (c, next) => {
  const key = c.req.header(API_KEY_HEADER) ?? c.req.header("X-MandateRail-Key");
  if (key) {
    const result = validateMerchantApiKeyPrefix(key);
    if (!result.ok) {
      return c.json(
        { error: result.error, message: result.message },
        result.status,
      );
    }
  }
  await next();
});

app.get("/health", (c) =>
  c.json({
    ok: true,
    service: "mandaterail-demo-api",
    network: NETWORK,
    merchant: MERCHANT_ADDRESS || null,
    asset: USDC_ASA,
  }),
);

app.get("/", (c) =>
  c.json({
    name: "MandateRail demo-api",
    endpoints: {
      health: "GET /health",
      unpaidExample: "GET /paid/resource (no headers → 402)",
      registerMandate: "POST /demo/mandates",
      getMandate: "GET /demo/mandates/:id",
      preview402: "GET /402-preview",
      listReceipts: "GET /receipts",
      getReceipt: "GET /receipts/:receiptId",
    },
    notes: {
      merchant:
        "MERCHANT_ADDRESS is receive-only payTo; ALGORAND_MNEMONIC is the payer (scripts)",
    },
  }),
);

mountDemoMandates(app, demoStore, {
  remoteAddress: (c) => {
    try {
      return getConnInfo(c).remote.address;
    } catch {
      return undefined;
    }
  },
});

app.get("/receipts", async (c) => {
  const limitRaw = c.req.query("limit");
  const limit = limitRaw ? Number(limitRaw) : 50;
  return c.json({
    receipts: await listReceipts(Number.isFinite(limit) ? limit : 50),
  });
});

app.get("/receipts/:receiptId", async (c) => {
  const r = await getReceipt(c.req.param("receiptId"));
  if (!r) return c.json({ error: "not_found" }, 404);
  return c.json(r);
});

if (!MERCHANT_ADDRESS) {
  console.warn(
    "WARN: MERCHANT_ADDRESS is not set — 402 payTo will be empty. Set MERCHANT_ADDRESS to your Algorand receive address (distinct from the payer mnemonic).",
  );
}

const paidConfig = {
  merchantId: "demo-merchant",
  amount: PRICE_HUMAN,
  asset: "USDC",
  payTo: MERCHANT_ADDRESS,
  network: NETWORK,
  assetId: USDC_ASA,
  decimals: 6,
  feePayer: FEE_PAYER,
  maxTimeoutSeconds: 60,
  // T7: per-payment + per-day-per-payer caps over the receipts store.
  spend: { store: spendStore },
  loadMandate: async ({
    mandateId,
    rawHeader,
  }: {
    mandateId: string | undefined;
    rawHeader: string | undefined;
    c?: unknown;
  }) => {
    if (mandateId && demoStore.has(mandateId)) {
      return demoStore.get(mandateId)!;
    }
    if (rawHeader?.trim().startsWith("{")) {
      try {
        return JSON.parse(rawHeader);
      } catch {
        /* fall through */
      }
    }
    return null;
  },
  facilitator:
    process.env.DEMO_MOCK_FACILITATOR === "true"
      ? ({
          verify: async () => ({
            ok: true as const,
            status: 200,
            data: { mock: true, isValid: true },
          }),
          settle: async () => ({
            ok: true as const,
            status: 200,
            data: {
              mock: true,
              success: true,
              transaction: `MOCK_TX_${Date.now()}`,
              warning: "DEMO_MOCK_FACILITATOR",
            },
          }),
        } as unknown as ReturnType<typeof createGoPlausibleClient>)
      : createGoPlausibleClient(),
};

// P2-T10 kill switch: paid routes refuse before any payment work while paused.
app.use("/paid/*", async (c, next) => {
  const p = pauseState();
  if (p.paused) {
    c.header("Cache-Control", "no-store");
    return c.json({ ...PAUSED_BODY, reason: p.reason }, 503);
  }
  await next();
});

app.get("/paid/resource", mandateRail(paidConfig), async (c) => {
  const mandate = c.get("mandate");
  const settle = c.get("facilitatorSettle");
  const requirements = c.get("paymentRequirements");

  let receiptId: string | undefined;
  let explorerUrl: string | undefined;

  const txId = extractTxId(settle);
  if (txId && mandate) {
    const receipt = await persistReceipt({
      mandateId: mandate.id,
      txId,
      network: requirements?.network ?? NETWORK,
      payer: mandate.principal,
      merchant: requirements?.payTo ?? MERCHANT_ADDRESS,
      amount: PRICE_HUMAN,
      asset: requirements?.asset ?? USDC_ASA,
    });
    receiptId = receipt.receiptId;
    explorerUrl = receipt.explorerUrl;
  }

  return c.json({
    ok: true,
    resource: "secret-demo-payload",
    mandateId: mandate?.id,
    settle,
    receiptId: receiptId ?? null,
    explorerUrl: explorerUrl ?? null,
  });
});

app.get("/402-preview", (c) => c.json(paymentRequiredBody(paidConfig), 402));

if (!isLoopbackHost(HOST)) {
  console.warn(
    `[demo-api] WARNING: bind host is ${HOST} (not loopback). Prefer DEMO_API_HOST=127.0.0.1; do not expose beyond loopback without auth. Default is 127.0.0.1.`,
  );
}

console.log(`MandateRail demo-api listening on http://${HOST}:${PORT}`);
console.log(
  `  MERCHANT_ADDRESS (payTo/receive-only)=${MERCHANT_ADDRESS || "(unset)"}`,
);
console.log(`  NETWORK=${NETWORK}`);
console.log(`  DEMO_MANDATES_WRITE=${demoWriteMode()} (max ${demoStore.limits.maxEntries}, ttl ${demoStore.limits.ttlMs}ms)`);
console.log(`  USDC_ASA=${USDC_ASA}`);
console.log(`  FEE_PAYER=${FEE_PAYER}`);
console.log(`  PRICE_USDC=${PRICE_HUMAN}`);
console.log(`  RECEIPTS_PATH=${receiptsPath()}`);
console.log(
  `  DEV_ALLOW_UNSIGNED=${process.env.DEV_ALLOW_UNSIGNED ?? "false"}`,
);
console.log(
  `  DEMO_MOCK_FACILITATOR=${process.env.DEMO_MOCK_FACILITATOR ?? "false"}`,
);
console.log(`  Try: curl -si http://127.0.0.1:${PORT}/paid/resource`);

serve({ fetch: app.fetch, port: PORT, hostname: HOST });

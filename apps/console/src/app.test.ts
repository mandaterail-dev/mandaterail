import { mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { closeStateTestBackend, prepareStateTestBackend, stateTestBackend, stateTestBackendKind } from "@mandaterail/storage/testing";

// R19-P3-5: real Postgres/Redis under scripts/with-state-services.sh.
beforeAll(prepareStateTestBackend);
afterAll(closeStateTestBackend);
it("R19-P3-5: state backend for this run matches the environment", () => {
  expect(stateTestBackendKind()).toBe(!process.env.MR_TEST_PG_URL ? "memory" : process.env.MR_TEST_REDIS_URL ? "redis+postgres" : "postgres");
  expect(Boolean(stateTestBackend())).toBe(Boolean(process.env.MR_TEST_PG_URL));
});
import algosdk from "algosdk";
import { ALGORAND_MAINNET_CAIP2, ALGORAND_TESTNET_CAIP2, encodeAttestationHeader, signMandate } from "@mandaterail/core";
import { createConsoleApp } from "./app.js";
import { checkConsoleGate } from "./gate.js";
import { createMandate, listMandates, revokeMandate, StoreFullError } from "./store.js";

const op = algosdk.generateAccount();
const OP = op.addr.toString();
const ATT = "x-mandaterail-operator-attestation";
const ENV_KEYS = [
  "NETWORK", "ALLOW_MAINNET", "ALLOW_INSECURE_DEV", "OPERATOR_ATTESTATION_MODE", "OPERATOR_ALLOWLIST",
  "OPERATOR_SIGNDATA_DOMAIN", "AC2_OPERATOR_TOKEN", "AC2_BRIDGE_TRUSTED_PROXY_HOPS", "CORS_ORIGINS",
  "CONSOLE_RATE_PER_IP", "CONSOLE_RATE_GLOBAL", "CONSOLE_MAX_BODY_BYTES", "CONSOLE_MAX_MANDATES",
  "CONSOLE_DATA_DIR", "CONSOLE_HOST", "CONSOLE_CHALLENGE_AUDIENCE",
];
const saved: Record<string, string | undefined> = {};
let dir = "";
beforeEach(() => {
  for (const k of ENV_KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
  dir = mkdtempSync(path.join(tmpdir(), "mr-console-"));
  process.env.CONSOLE_DATA_DIR = dir;
  process.env.NETWORK = ALGORAND_TESTNET_CAIP2;
  process.env.OPERATOR_ATTESTATION_MODE = "signed-challenge";
  process.env.OPERATOR_ALLOWLIST = OP;
  process.env.OPERATOR_SIGNDATA_DOMAIN = "mandaterail.pages.dev";
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
  for (const k of ENV_KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
});

const make = () => createConsoleApp({ remoteAddress: (c) => c.req.header("x-test-ip") ?? "127.0.0.1", backend: stateTestBackend() });
type App = ReturnType<typeof make>["app"];
/** Seed legacy records the way each backend holds them (file JSON or the shared store), then build the app. */
async function makeSeeded(records: unknown[]) {
  const be = stateTestBackend();
  if (!be) {
    writeFileSync(path.join(dir, "mandates.json"), JSON.stringify(records));
    return createConsoleApp({ remoteAddress: (c) => c.req.header("x-test-ip") ?? "127.0.0.1" });
  }
  const m = be.mandates("console");
  for (const r of records) await m.create(r as never, { signatureVerified: false });
  return createConsoleApp({ remoteAddress: (c) => c.req.header("x-test-ip") ?? "127.0.0.1", backend: be });
}
const json = async (r: Response) => (await r.json()) as Record<string, any>;

async function evidence(app: App, action: string, id: string, signer = op, forge = false) {
  const res = await app.request(`/operator/challenge?action=${action}&id=${encodeURIComponent(id)}`);
  expect(res.status).toBe(200);
  const ch = await json(res);
  const sig = forge ? new Uint8Array(64).fill(9) : algosdk.signBytes(new TextEncoder().encode(ch.message), signer.sk);
  return encodeAttestationHeader({ nonce: ch.nonce, address: signer.addr.toString(), format: "algosdk", signature: Buffer.from(sig).toString("base64") });
}

const createReq = (app: App, id: string, headers: Record<string, string> = {}) =>
  app.request("/mandates", { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify({ id }) });

/** route table: action, subject, request */
const routes = (app: App, id: string) => [
  { action: "mandate.list", subject: "mandates", req: (h: Record<string, string>) => app.request("/mandates", { headers: h }) },
  { action: "mandate.read", subject: id, req: (h: Record<string, string>) => app.request(`/mandates/${id}`, { headers: h }) },
  { action: "mandate.create", subject: "m-new", req: (h: Record<string, string>) => createReq(app, "m-new", h) },
  { action: "mandate.revoke", subject: id, req: (h: Record<string, string>) => app.request(`/mandates/${id}/revoke`, { method: "POST", headers: h }) },
  { action: "mandate.read", subject: id, req: (h: Record<string, string>) => app.request(`/mandates/${id}/authorize-check`, { method: "POST", headers: h }) },
];

async function seed(app: App, id = "m-1") {
  const r = await createReq(app, id, { [ATT]: await evidence(app, "mandate.create", id) });
  expect(r.status).toBe(201);
}

describe("console signed-challenge routes", () => {
  it("valid allowlisted attestation: create, list, read, revoke", async () => {
    const { app } = make();
    await seed(app);
    const list = await app.request("/mandates", { headers: { [ATT]: await evidence(app, "mandate.list", "mandates") } });
    expect(list.status).toBe(200);
    expect(list.headers.get("cache-control")).toBe("no-store");
    expect((await json(list)).items.map((m: any) => m.id)).toEqual(["m-1"]);
    const read = await app.request("/mandates/m-1", { headers: { [ATT]: await evidence(app, "mandate.read", "m-1") } });
    expect((await json(read)).authorization.status).toBe("unsigned-draft");
    const rev = await app.request("/mandates/m-1/revoke", { method: "POST", headers: { [ATT]: await evidence(app, "mandate.revoke", "m-1") } });
    expect((await json(rev)).revoked).toBe(true);
    // unknown id: 404 only after auth
    expect((await app.request("/mandates/nope", { headers: { [ATT]: await evidence(app, "mandate.read", "nope") } })).status).toBe(404);
  });

  it("unauthenticated reads and writes -> 401", async () => {
    const { app } = make();
    await seed(app);
    for (const r of routes(app, "m-1")) expect((await r.req({})).status, r.action).toBe(401);
  });

  it("forged signatures -> 401 and nothing changes", async () => {
    const { app } = make();
    await seed(app);
    for (const r of routes(app, "m-1")) {
      expect((await r.req({ [ATT]: await evidence(app, r.action, r.subject, op, true) })).status, r.action).toBe(401);
    }
    const m = await json(await app.request("/mandates/m-1", { headers: { [ATT]: await evidence(app, "mandate.read", "m-1") } }));
    expect(m.revoked).toBe(false);
  });

  it("valid signature from a non-allowlisted signer -> 401", async () => {
    const { app } = make();
    await seed(app);
    const stranger = algosdk.generateAccount();
    for (const r of routes(app, "m-1")) {
      expect((await r.req({ [ATT]: await evidence(app, r.action, r.subject, stranger) })).status, r.action).toBe(401);
    }
  });

  it("challenge is bound to action and id", async () => {
    const { app } = make();
    await seed(app);
    await seed(app, "m-2");
    // read evidence cannot revoke; m-2 evidence cannot read m-1
    expect((await app.request("/mandates/m-1/revoke", { method: "POST", headers: { [ATT]: await evidence(app, "mandate.read", "m-1") } })).status).toBe(401);
    expect((await app.request("/mandates/m-1", { headers: { [ATT]: await evidence(app, "mandate.read", "m-2") } })).status).toBe(401);
    // create evidence bound to a different id
    expect((await createReq(app, "m-3", { [ATT]: await evidence(app, "mandate.create", "m-4") })).status).toBe(401);
    // create without id
    expect((await app.request("/mandates", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" })).status).toBe(400);
    // bridge actions are not console actions
    expect((await app.request("/operator/challenge?action=approve&id=m-1")).status).toBe(400);
  });

  it("CORS: allowlisted origin gets headers, others do not; preflight 204", async () => {
    process.env.CORS_ORIGINS = "https://mandaterail.pages.dev";
    const { app } = make();
    const ok = await app.request("/health", { headers: { origin: "https://mandaterail.pages.dev" } });
    expect(ok.headers.get("access-control-allow-origin")).toBe("https://mandaterail.pages.dev");
    expect(ok.headers.get("access-control-allow-headers")).toMatch(/X-MandateRail-Operator-Attestation/);
    const bad = await app.request("/health", { headers: { origin: "https://evil.example" } });
    expect(bad.headers.get("access-control-allow-origin")).toBeNull();
    const pre = await app.request("/mandates", { method: "OPTIONS", headers: { origin: "https://mandaterail.pages.dev" } });
    expect(pre.status).toBe(204);
  });

  it("rate limit 429, body limit 413, store cap 503", async () => {
    process.env.CONSOLE_RATE_PER_IP = "3";
    process.env.CONSOLE_RATE_GLOBAL = "10";
    process.env.CONSOLE_MAX_BODY_BYTES = "1024";
    const { app } = make();
    for (let i = 0; i < 3; i++) expect((await app.request("/mandates", { headers: { "x-test-ip": "10.1.1.1" } })).status).toBe(401);
    const limited = await app.request("/mandates", { headers: { "x-test-ip": "10.1.1.1" } });
    expect(limited.status).toBe(429);
    expect(limited.headers.get("retry-after")).toBe("60");
    const big = await app.request("/mandates", { method: "POST", headers: { "content-type": "application/json", "x-test-ip": "10.2.2.2" }, body: JSON.stringify({ id: "m-x", pad: "x".repeat(2000) }) });
    expect(big.status).toBe(413);

    delete process.env.CONSOLE_RATE_PER_IP;
    delete process.env.CONSOLE_RATE_GLOBAL;
    process.env.CONSOLE_MAX_MANDATES = "1";
    const { app: app2 } = make();
    await seed(app2, "only");
    const full = await createReq(app2, "two", { [ATT]: await evidence(app2, "mandate.create", "two") });
    expect(full.status).toBe(503);
    expect((await json(full)).error).toBe("store_full");
  });
});

describe("console local-only mode (not signed-challenge)", () => {
  it("direct loopback allowed; non-loopback or any forwarding header -> 401", async () => {
    process.env.OPERATOR_ATTESTATION_MODE = "token-lab";
    const { app } = make();
    expect((await createReq(app, "m-1")).status).toBe(201);
    expect((await app.request("/mandates")).status).toBe(200);
    expect((await app.request("/mandates", { headers: { "x-test-ip": "10.0.0.1" } })).status).toBe(401);
    for (const h of ["x-forwarded-for", "cf-connecting-ip", "via", "forwarded"]) {
      expect((await app.request("/mandates", { headers: { [h]: "1.2.3.4" } })).status, h).toBe(401);
      expect((await app.request("/mandates/m-1/revoke", { method: "POST", headers: { [h]: "1.2.3.4" } })).status, h).toBe(401);
    }
    expect((await app.request("/operator/challenge?action=mandate.list&id=mandates")).status).toBe(404);
  });
});

describe("console startup gate", () => {
  it("refuses non-loopback bind without signed-challenge", () => {
    process.env.OPERATOR_ATTESTATION_MODE = "token-lab";
    expect(checkConsoleGate({ bindHost: "127.0.0.1" }).ok).toBe(true);
    const r = checkConsoleGate({ bindHost: "0.0.0.0" });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/signed-challenge/);
    expect(checkConsoleGate({ bindHost: "127.example.com" }).ok).toBe(false);
  });
  it("refuses proxied local-only mode (hops > 0)", () => {
    process.env.OPERATOR_ATTESTATION_MODE = "token-lab";
    process.env.AC2_BRIDGE_TRUSTED_PROXY_HOPS = "1";
    process.env.AC2_OPERATOR_TOKEN = "t";
    expect(checkConsoleGate({ bindHost: "127.0.0.1" }).ok).toBe(false);
  });
  it("signed-challenge requires allowlist and domain", () => {
    expect(checkConsoleGate({ bindHost: "0.0.0.0" }).ok).toBe(true);
    delete process.env.OPERATOR_SIGNDATA_DOMAIN;
    expect(checkConsoleGate({ bindHost: "0.0.0.0" }).ok).toBe(false);
    process.env.OPERATOR_SIGNDATA_DOMAIN = "mandaterail.pages.dev";
    delete process.env.OPERATOR_ALLOWLIST;
    expect(checkConsoleGate({ bindHost: "0.0.0.0" }).ok).toBe(false);
  });
  it("refuses MainNet token-lab and out-of-range limits", () => {
    process.env.NETWORK = ALGORAND_MAINNET_CAIP2;
    process.env.OPERATOR_ATTESTATION_MODE = "token-lab";
    expect(checkConsoleGate({ bindHost: "127.0.0.1" }).ok).toBe(false);
    process.env.NETWORK = ALGORAND_TESTNET_CAIP2;
    process.env.OPERATOR_ATTESTATION_MODE = "signed-challenge";
    process.env.CONSOLE_MAX_BODY_BYTES = "100";
    expect(checkConsoleGate().ok).toBe(false);
    delete process.env.CONSOLE_MAX_BODY_BYTES;
    process.env.CONSOLE_RATE_PER_IP = "50";
    process.env.CONSOLE_RATE_GLOBAL = "10";
    expect(checkConsoleGate().ok).toBe(false);
  });
});

describe("console run-12 coverage", () => {
  it("authorize-check: positive for a verified signature, refuses unsigned draft", async () => {
    const principal = algosdk.generateAccount();
    const base = {
      id: "m-signed",
      principal: principal.addr.toString(),
      agent: "did:example:agent-1",
      maxAmount: "5.00",
      asset: "USDC",
      allowlist: ["demo-merchant"],
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      revoked: false,
      nonce: "n-1",
      createdAt: new Date().toISOString(),
    };
    const signedMandate = { ...base, signature: signMandate(base as any, principal.sk) };

    const { app } = await makeSeeded([signedMandate]);
    const ok = await app.request("/mandates/m-signed/authorize-check", {
      method: "POST",
      headers: { "content-type": "application/json", [ATT]: await evidence(app, "mandate.read", "m-signed") },
      body: JSON.stringify({ merchantId: "demo-merchant", amount: "5.00", asset: "USDC" }),
    });
    const okBody = await json(ok);
    expect(ok.status, JSON.stringify(okBody)).toBe(200);
    expect(okBody.authorization.authorizedForExecute).toBe(true);

    await seed(app, "m-draft");
    const draft = await app.request("/mandates/m-draft/authorize-check", {
      method: "POST", headers: { [ATT]: await evidence(app, "mandate.read", "m-draft") },
    });
    expect(draft.status).toBe(403);
    expect((await json(draft)).authorization.status).toBe("unsigned-draft");
  });

  it("a real bridge nonce replayed at the console is rejected", async () => {
    const bridgePath = "../../ac2-bridge/src/app.js";
    const { createBridgeApp } = (await import(bridgePath)) as { createBridgeApp: (o?: any) => { app: App } };
    const { app: bridge } = createBridgeApp({ remoteAddress: () => "127.0.0.1" });
    const res = await bridge.request("/operator/challenge?action=approve&id=m-1");
    expect(res.status).toBe(200);
    const ch = await json(res);
    const sig = algosdk.signBytes(new TextEncoder().encode(ch.message), op.sk);
    const header = encodeAttestationHeader({ nonce: ch.nonce, address: OP, format: "algosdk", signature: Buffer.from(sig).toString("base64") });
    const { app } = make();
    await seed(app, "m-1");
    expect((await app.request("/mandates/m-1/revoke", { method: "POST", headers: { [ATT]: header } })).status).toBe(401);
    expect((await app.request("/mandates", { headers: { [ATT]: header } })).status).toBe(401);
  });

  it("hops=1 keys the rate limit on X-Forwarded-For", async () => {
    process.env.AC2_BRIDGE_TRUSTED_PROXY_HOPS = "1";
    process.env.CONSOLE_RATE_PER_IP = "2";
    process.env.CONSOLE_RATE_GLOBAL = "50";
    const { app } = make();
    const req = (xff: string) => app.request("/mandates", { headers: { "x-test-ip": "10.9.9.9", "x-forwarded-for": xff } });
    expect((await req("203.0.113.1")).status).toBe(401);
    expect((await req("198.51.100.7, 203.0.113.1")).status).toBe(401);
    expect((await req("203.0.113.1")).status).toBe(429);
    // same proxy socket, different client: own bucket
    expect((await req("203.0.113.2")).status).toBe(401);
  });

  it("local-only create without id gets a UUID; create_failed is generic", async () => {
    process.env.OPERATOR_ATTESTATION_MODE = "token-lab";
    const { app } = make();
    const r = await app.request("/mandates", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    expect(r.status).toBe(201);
    expect((await json(r)).id).toMatch(/^[0-9a-f-]{36}$/);
    expect((await createReq(app, "dup")).status).toBe(201);
    const dup = await createReq(app, "dup");
    expect(dup.status).toBe(409);
    const body = await json(dup);
    expect(body).toEqual({ error: "create_failed", message: "mandate could not be created" });
  });
});

describe("console store concurrency", () => {
  const mk = (id: string) => ({
    id, principal: "did:example:alice", agent: "did:example:agent-1", maxAmount: "1.00", asset: "USDC",
    allowlist: ["m"], expiresAt: new Date(Date.now() + 3600_000).toISOString(), nonce: id, signature: null,
  });

  it("concurrent create + revoke never resurrects a revoked mandate", async () => {
    await createMandate(mk("victim") as any);
    await Promise.all([
      revokeMandate("victim"),
      ...Array.from({ length: 20 }, (_, i) => createMandate(mk(`c-${i}`) as any)),
    ]);
    const all = await listMandates();
    expect(all.find((m) => m.mandate.id === "victim")?.mandate.revoked).toBe(true);
    expect(all).toHaveLength(21);
  });

  it("concurrent creates never exceed the cap", async () => {
    const results = await Promise.allSettled(
      Array.from({ length: 25 }, (_, i) => createMandate(mk(`k-${i}`) as any, { maxMandates: 10 })),
    );
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(10);
    expect(results.filter((r) => r.status === "rejected").every((r) => (r as PromiseRejectedResult).reason instanceof StoreFullError)).toBe(true);
    expect(await listMandates()).toHaveLength(10);
    expect(readdirSync(dir).filter((f) => f.endsWith(".tmp"))).toEqual([]);
  });
});

describe("console signed create (end-to-end)", () => {
  const principal = algosdk.generateAccount();
  const signedBody = (id: string) => {
    const base = {
      id, principal: principal.addr.toString(), agent: "did:example:agent-1", maxAmount: "5.00", asset: "USDC",
      allowlist: ["demo-merchant"], expiresAt: new Date(Date.now() + 3600_000).toISOString(), revoked: false,
      nonce: `n-${id}`, createdAt: new Date().toISOString(),
    };
    return { ...base, signature: signMandate(base as any, principal.sk) };
  };
  const post = async (app: App, body: Record<string, unknown>) =>
    app.request("/mandates", { method: "POST", headers: { "content-type": "application/json", [ATT]: await evidence(app, "mandate.create", String(body.id)) }, body: JSON.stringify(body) });

  it("POST /mandates with a client signature, then authorize-check -> 200", async () => {
    const { app } = make();
    const body = signedBody("m-e2e");
    const created = await post(app, body);
    const cj = await json(created);
    expect(created.status, JSON.stringify(cj)).toBe(201);
    expect(cj.authorization.status).toBe("signature-verified");
    expect(cj.metadata).toBeUndefined();
    expect(cj.createdAt).toBe(body.createdAt);
    const chk = await app.request("/mandates/m-e2e/authorize-check", {
      method: "POST",
      headers: { "content-type": "application/json", [ATT]: await evidence(app, "mandate.read", "m-e2e") },
      body: JSON.stringify({ merchantId: "demo-merchant", amount: "5.00", asset: "USDC" }),
    });
    const kj = await json(chk);
    expect(chk.status, JSON.stringify(kj)).toBe(200);
    expect(kj.authorization.authorizedForExecute).toBe(true);
  });

  it("rejects signed creates that are tampered, lack createdAt, or carry unknown fields", async () => {
    const { app, stores } = make();
    const tampered = { ...signedBody("m-t"), maxAmount: "500.00" };
    expect((await json(await post(app, tampered))).error).toBe("invalid_signature");
    const { createdAt: _c, ...noCreated } = signedBody("m-c");
    expect((await json(await post(app, noCreated))).error).toBe("signed_create_requires_createdAt");
    const extra = { ...signedBody("m-x"), zzUnknown: 1 };
    const r = await post(app, extra);
    expect(r.status).toBe(400);
    expect(["signed_fields_changed", "invalid_mandate"]).toContain((await json(r)).error);
    expect(await stores.mandates.list()).toHaveLength(0);
  });
});

describe("console run-13: principal binding, createdAt, revoked, verified flag", () => {
  const victim = algosdk.generateAccount();
  const attacker = algosdk.generateAccount();
  const pkB64 = (a: algosdk.Account) => Buffer.from(algosdk.decodeAddress(a.addr.toString()).publicKey).toString("base64");
  const body = (id: string, principal: string, signer: algosdk.Account, over: Record<string, unknown> = {}) => {
    const base = {
      id, principal, agent: "did:example:agent-1", maxAmount: "5.00", asset: "USDC", allowlist: ["demo-merchant"],
      expiresAt: new Date(Date.now() + 3600_000).toISOString(), revoked: false, nonce: `n-${id}`,
      createdAt: new Date().toISOString(), ...over,
    };
    return { ...base, signature: signMandate(base as any, signer.sk) };
  };
  const post = async (app: App, b: Record<string, unknown>) =>
    app.request("/mandates", { method: "POST", headers: { "content-type": "application/json", [ATT]: await evidence(app, "mandate.create", String(b.id)) }, body: JSON.stringify(b) });
  const check = async (app: App, id: string) =>
    app.request(`/mandates/${id}/authorize-check`, { method: "POST", headers: { [ATT]: await evidence(app, "mandate.read", id) } });

  it("allowlisted operator signing for another principal is rejected at create", async () => {
    const { app, stores } = make();
    const forged = { ...body("m-f1", victim.addr.toString(), attacker), principalPubkey: pkB64(attacker) };
    const r1 = await post(app, forged);
    expect(r1.status).toBe(400);
    expect((await json(r1)).error).toBe("invalid_signature");
    const r2 = await post(app, body("m-f2", victim.addr.toString(), attacker));
    expect((await json(r2)).error).toBe("invalid_signature");
    const r3 = await post(app, { ...body("m-f3", "did:example:victim", attacker), principalPubkey: pkB64(attacker) });
    expect(r3.status).toBe(400);
    expect(await stores.mandates.list()).toHaveLength(0);
  });

  it("forged-principal record is refused at authorize-check; the right principal passes", async () => {
    const forged = { ...body("m-f", victim.addr.toString(), attacker), principalPubkey: pkB64(attacker), metadata: { draftStatus: "signature-verified" } };

    const { app } = await makeSeeded([forged]);
    const read = await app.request("/mandates/m-f", { headers: { [ATT]: await evidence(app, "mandate.read", "m-f") } });
    // client-written draftStatus is not trusted
    expect((await json(read)).authorization.status).toBe("signature-present-unverified");
    const bad = await check(app, "m-f");
    expect(bad.status).toBe(403);
    expect((await json(bad)).ok).toBe(false);

    const good = await post(app, { ...body("m-ok", victim.addr.toString(), victim), principalPubkey: pkB64(victim) });
    expect(good.status).toBe(201);
    const ok = await check(app, "m-ok");
    expect(ok.status).toBe(200);
  });

  it("signed create stores a server-side verified flag (not metadata)", async () => {
    const { app, stores } = make();
    const r = await post(app, body("m-v", victim.addr.toString(), victim));
    expect(r.status).toBe(201);
    const read = await app.request("/mandates/m-v", { headers: { [ATT]: await evidence(app, "mandate.read", "m-v") } });
    const rj = await json(read);
    expect(rj.authorization.status).toBe("signature-verified");
    expect(rj.metadata).toBeUndefined();
    const stored = (await stores.mandates.list())[0]!;
    expect(stored.server.signatureVerified).toBe(true);
  });

  it("createdAt must be ISO and within skew; revoked creates are rejected", async () => {
    const { app } = make();
    const addr = victim.addr.toString();
    for (const createdAt of ["yesterday", "2026-10-13", new Date(Date.now() - 3600_000).toISOString(), new Date(Date.now() + 3600_000).toISOString()]) {
      const r = await post(app, body(`m-c${createdAt.length}`, addr, victim, { createdAt }));
      expect(r.status, createdAt).toBe(400);
      expect((await json(r)).error, createdAt).toBe("invalid_createdAt");
    }
    const rv = await post(app, body("m-rev", addr, victim, { revoked: true }));
    expect((await json(rv)).error).toBe("already_revoked");
    const ur = await app.request("/mandates", { method: "POST", headers: { "content-type": "application/json", [ATT]: await evidence(app, "mandate.create", "m-rev3") }, body: JSON.stringify({ id: "m-rev3", revoked: true }) });
    expect((await json(ur)).error).toBe("already_revoked");
  });
});

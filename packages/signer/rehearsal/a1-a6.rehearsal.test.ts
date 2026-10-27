/**
 * Rehearsal A1-A6 (internal reviewer run 44), TestNet only, on the box. Opt-in: MR_REHEARSAL=1 + MR_TEST_PG_URL +
 * MR_NTFY_TOPIC (the TestNet-only topic from the 0600 env file; never printed). Writes proofs to MR_REHEARSAL_OUT.
 *
 * Real: Nodely TestNet indexer + algod (HTTP probes), ntfy.sh publishes, PG18 + mr_ed25519 + v11/v12 (local test DB,
 * not ECS), mr-signer main (HTTP server, audit chain, heartbeat), the helper over a real Unix socket.
 * STAND-INS (labeled in the proofs): the audit sink (TESTNET-ONLY local append file; no B2 account yet), the
 * second "operator" (testnet-api.algonode.cloud is the SAME operator as Nodely; no free second operator exists),
 * the software Ed25519 key (TESTNET-ONLY, no YubiKey on the box), the clock source (no chrony on the box: offset
 * from algod's HTTP Date header), and the helper's clock (advanced by the
 * harness to skip the 10-minute lockout waits).
 */
import { sign as edSign } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { execFile } from "node:child_process";
import { copyFileSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import pg from "pg";
import algosdk from "algosdk";
import { toMicro } from "@mandaterail/core";
import { isoSeconds, keyIdOf, migratePostgres, PgSpendStore } from "@mandaterail/storage";
import { attestedRelease, type SignerTransport } from "../src/cli/release.js";
import { startMain, type MainConfigFile, type Running } from "../src/main.js";
import { HttpProbe } from "../src/providers.js";
import { STANDIN_LABEL } from "../src/sinks/local-standin.js";
import { ntfyPager } from "../src/pager.js";
import { DurableJson } from "../src/state.js";
import { initialReqState, RequestAuth, signRequest, type ReqState, type SignedRequest } from "../src/requests.js";
import { helperSocketServer, HelperSocketClient } from "../src/piv/socket.js";
import { PivHelper, initialHelperState } from "../src/piv/helper.js";
import { UsedStore } from "../src/piv/used-store.js";
import { RollbackDetected } from "../src/audit.js";

const ON = process.env.MR_REHEARSAL === "1" && !!process.env.MR_TEST_PG_URL && !!process.env.MR_NTFY_TOPIC;
const TN = "SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=";
const ALGOD = "https://testnet-api.4160.nodely.dev", IDX = "https://testnet-idx.4160.nodely.dev";
const OP_A = "nodely", OP_B = "standin-same-operator-nodely-algonode";
const SQL = path.resolve(__dirname, "../../../deploy/sql/t11-mr-reconcile-role.sql");
const proof: Record<string, unknown> = { startedAt: new Date().toISOString(), network: "testnet", genesis: TN, standIns: [] };
const log = (k: string, v: unknown) => { proof[k] = v; };
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const payer = algosdk.generateAccount(), merchant = algosdk.generateAccount();
const edKey = () => { const { publicKey, privateKey } = generateKeyPairSync("ed25519"); return { pub: new Uint8Array(publicKey.export({ format: "der", type: "spki" }).subarray(12)), priv: privateKey }; };
const requester = edKey();
let own: pg.Pool, rel: pg.Pool, admin: pg.Pool;
let dir: string, helperSock: string, helper: PivHelper, helperSrv: ReturnType<typeof helperSocketServer>;
let skewMs = 0;
let main: Running; let f: MainConfigFile; let pub: Uint8Array;
const sentConfirms: SignedRequest[] = [];
let pings = 0;

async function json(u: string): Promise<Record<string, unknown>> { const r = await fetch(u); return (await r.json()) as Record<string, unknown>; }
const clock = async () => {
  const t0 = Date.now(); const r = await fetch(`${ALGOD}/health`); const t1 = Date.now();
  const d = Date.parse(r.headers.get("date") ?? ""); const offsetS = (d + 500 - (t0 + t1) / 2) / 1000;
  return { synced: Number.isFinite(offsetS), offsetS: Math.abs(offsetS) < 1.5 ? offsetS : offsetS, stratum: 2 };
};

function transport(): SignerTransport {
  const port = (main.server.address() as { port: number }).port;
  const post = async (route: string, body: SignedRequest) => {
    const r = await fetch(`http://127.0.0.1:${port}/v1/${route}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    const j = (await r.json()) as Record<string, string>;
    if (r.status !== 200) throw new Error(`signer HTTP ${r.status} ${j.error}`);
    return j as never;
  };
  return { candidate: (q) => post("candidate", q), confirm: (q) => { sentConfirms.push(q); return post("confirm", q); } };
}

async function newAmbiguousSpend(store: string, id: string) {
  const st = await json(`${ALGOD}/v2/status`); const R = Number(st["last-round"]);
  const fv = R - 30, lv = R - 15;
  const t = algosdk.makeAssetTransferTxnWithSuggestedParamsFromObject({ sender: payer.addr, receiver: merchant.addr, amount: 10_000n, assetIndex: 10458941,
    suggestedParams: { fee: 1000n, minFee: 1000n, flatFee: true, firstValid: BigInt(fv), lastValid: BigInt(lv), genesisHash: Buffer.from(TN, "base64"), genesisID: "testnet-v1.0" } } as never);
  const bytes = t.signTxn(payer.sk);
  const sp = new PgSpendStore(own, { store });
  await sp.reserve({ id, payer: payer.addr.toString(), amountMicro: 10_000n, caps: { perPaymentMicro: toMicro("1"), perDayMicro: toMicro("5") }, nowMs: Date.now() });
  const att = await sp.attachSignedTxn(id, { signedTxn: bytes, kind: "xpayment", payer: payer.addr.toString(), submitRound: lv - 1, nowMs: Date.now() } as never);
  expect(att).not.toBeNull();
  await sp.finalize(id, "ambiguous", Date.now());
  await sleep(3500); // lv_est = submit_at + 1 round (2.5 s); observations are whole seconds
  return { sp, txId: t.txID(), fv, lv, headAtBuild: R };
}

function cliDeps(page: (s: string, b: string) => Promise<void>) {
  const cfg = main.signer["d" as never]["cfg"] as never;
  return { db: rel, cfg, pinnedPubkey: pub, requesterId: "cli-david", requesterKey: requester.priv, transport: transport(),
    ownProbes: [new HttpProbe({ host: "testnet-idx.algonode.cloud", operator: OP_A, kind: "indexer", baseUrl: "https://testnet-idx.algonode.cloud" })],
    page, label: "rehearsal", reason: "R44 rehearsal" };
}

const reqBody = (key: typeof requester.priv, body: Record<string, unknown>, tsMs = Date.now()) =>
  signRequest({ requester: "cli-david", network: "testnet", ts: isoSeconds(tsMs), reqNonce: randomBytes(32).toString("base64url"), ...body } as never, key);

async function boot(over: Partial<MainConfigFile> = {}, pager?: (s: string, b: string) => Promise<void>) {
  return startMain({ ...f, ...over }, { MR_NTFY_TOPIC: process.env.MR_NTFY_TOPIC }, { clock, ping: async () => { pings++; }, ...(pager ? { pager } : {}) });
}
const stop = (r: Running) => { r.stopHeartbeat(); r.server.close(); };

describe.skipIf(!ON)("Rehearsal A1-A6 on TestNet", () => {
  beforeAll(async () => {
    admin = new pg.Pool({ connectionString: process.env.MR_TEST_PG_URL, max: 2 });
    const db = `mr_reh_${randomBytes(4).toString("hex")}`;
    await admin.query(`CREATE DATABASE ${db}`);
    const url = process.env.MR_TEST_PG_URL!.replace(/\/[^/]*$/, `/${db}`);
    own = new pg.Pool({ connectionString: url, max: 4 });
    await migratePostgres(own, { network: "testnet", verifyNetwork: async (p) => ({ genesisHash: p.caip2.slice(9) }) });
    for (const [h, o] of [["testnet-idx.4160.nodely.dev", OP_A], ["testnet-api.algonode.cloud", OP_B], ["testnet-idx.algonode.cloud", OP_A]]) {
      await own.query("INSERT INTO mr_network_provider (network, host, operator_id) VALUES ('testnet', $1, $2) ON CONFLICT (network, host) DO UPDATE SET operator_id = EXCLUDED.operator_id", [h, o]); // local test DB only: the stand-in operator id
      await own.query("INSERT INTO mr_signer_operator (network, operator) VALUES ('testnet', $1) ON CONFLICT DO NOTHING", [o]);
    }
    await promisify(execFile)("psql", ["-X", "-q", "-v", "ON_ERROR_STOP=1", "-v", "pw=t-rec-pw", "-v", "mon_pw=t-mon-pw", "-v", "rel_pw=t-rel-pw", "-d", url, "-f", SQL]);
    const u = new URL(url); u.username = "mr_release"; u.password = "t-rel-pw";
    rel = new pg.Pool({ connectionString: u.toString(), max: 2 }); rel.on("error", () => undefined);

    dir = mkdtempSync(path.join(tmpdir(), "mr-reh-"));
    process.env.MR_SIGNER_SOFTWARE_KEY = "TESTNET-ONLY";
    const { SoftwareEd25519Backend } = await import("../src/piv/backend-software.js");
    const backend = new SoftwareEd25519Backend("testnet");
    pub = await backend.publicKey();
    const keyId = keyIdOf(pub);
    await own.query("INSERT INTO mr_signer_key (key_id, pubkey, network, margin_rounds, trust_domain, key_resource) VALUES ($1, $2, 'testnet', 10, 'gcp:mr-signer-test', 'projects/mr-signer-test/locations/us-east1/keyRings/mr/cryptoKeys/attest/cryptoKeyVersions/1')", [keyId, Buffer.from(pub)]);
    const now = () => Date.now() + skewMs;
    DurableJson.init(path.join(dir, "helper.json"), initialHelperState());
    DurableJson.init<ReqState>(path.join(dir, "helper-requests.json"), initialReqState());
    const hauth = new RequestAuth([{ id: "cli-david", pubkey: requester.pub }], new DurableJson<ReqState>(path.join(dir, "helper-requests.json")), { maxAgeS: 30, ratePerHour: 30, network: "testnet" }, now);
    helper = new PivHelper({ network: "testnet", keyId, payer: payer.addr.toString(), margin: 10, operators: [OP_A, OP_B], maxSignsPerHour: 5, maxSignsPer24h: 5 },
      backend, UsedStore.init(path.join(dir, "used.log")), hauth, new DurableJson(path.join(dir, "helper.json")), now);
    helperSock = path.join(dir, "helper.sock");
    helperSrv = helperSocketServer(helper, helperSock);
    f = {
      signer: {
        network: "testnet", genesisHash: TN, margin: 10, usdcAsaId: 10458941, payer: payer.addr.toString(), merchant: merchant.addr.toString(),
        feePayer: null, feePayerMaxFee: "2000", payerMaxFee: "1000", keyId,
        providers: [
          { host: "testnet-idx.4160.nodely.dev", operator: OP_A, kind: "indexer", baseUrl: IDX },
          { host: "testnet-api.algonode.cloud", operator: OP_B, kind: "algod", baseUrl: "https://testnet-api.algonode.cloud" },
        ],
        requesters: [{ id: "cli-david", pubkeyB64: Buffer.from(requester.pub).toString("base64") }], requesterRatePerHour: 30, requestMaxAgeS: 30,
        maxClockSkewS: 5, maxSnapshotAgeS: 60, maxHeadSpreadRounds: 20, attestTtlS: 600, /* R59-P3-1: the MainNet minimum */
        policy: { maxAmountMicro: "10000", maxReleasesPerHour: 5, maxReleasesPerDay: 5, maxReleasedMicroPerDay: "50000", windowUtcHours: [0, 24], anomalyPauseRefusalsPerHour: 6 },
      },
      attestPubkeyB64: Buffer.from(pub).toString("base64"), stateDir: dir, helperSocket: helperSock,
      listen: { host: "127.0.0.1", port: 0, allowIps: ["127.0.0.1"] },
      audit: { kind: "testnet-standin", minSeq: 0, label: STANDIN_LABEL, file: path.join(dir, "audit.jsonl") }, heartbeatIntervalS: 3600,
    };
    (proof.standIns as string[]).push(
      `audit sink: ${STANDIN_LABEL} (no B2 account in the owner's name yet)`,
      `second operator: ${OP_B} = testnet-api.algonode.cloud, which is the same operator as Nodely (no free second operator)`,
      "attestation key: SoftwareEd25519Backend TESTNET-ONLY (no YubiKey on the box)",
      "clock: offset from algod's HTTP Date header (no chrony on the box)",
      "helper clock: advanced by the harness to skip the 10-min lockout waits and the 6 h long lock (rev 21: no human unlock)",
      "dead-man ping: counted locally (no Healthchecks account yet)",
      "DB: local PG18 test database with migrations through v12 (never ECS); TestNet quorum 1, so the 2-of-2 co-sign path is not exercised here (only in test/verifier.test.ts)",
    );
    main = await boot();
    await sleep(1500);
    log("boot", { auditHeadSeq: main.audit.headSeq(), firstHeartbeat: main.heartbeats, realNtfyTestPublish: main.heartbeats[0] === true, pings });
  }, 120_000);

  afterAll(async () => {
    try { stop(main); } catch { /* */ }
    helperSrv?.close();
    proof.finishedAt = new Date().toISOString();
    proof.auditLog = readFileSync(path.join(dir, "audit.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l.split("\t")[0]!));
    if (process.env.MR_REHEARSAL_OUT) writeFileSync(process.env.MR_REHEARSAL_OUT, JSON.stringify(proof, null, 2));
    await rel?.end(); await own?.end(); await admin?.end();
  });

  let policySnapshot: string;
  it("A1: a never-submitted signed axfer, real absence on Nodely, released by the DB verifier", async () => {
    policySnapshot = path.join(dir, "policy.before-A1.json");
    copyFileSync(path.join(dir, "policy.json"), policySnapshot);
    const s = await newAmbiguousSpend("reh", "a1");
    const pages: string[] = [];
    const r = await attestedRelease(cliDeps(async (x, y) => { pages.push(`${x} ${y}`); }) as never, "reh", "a1");
    const idx = await fetch(`${IDX}/v2/transactions/${s.txId}`);
    const row = (await own.query("SELECT status, tx_id, first_valid, last_valid FROM mr_spend WHERE store='reh' AND id='a1'")).rows[0];
    const audit = (await own.query("SELECT action, from_status, to_status, actor FROM mr_spend_audit WHERE store='reh' AND id='a1' ORDER BY at_ms")).rows;
    const att = (await own.query("SELECT convert_from(substring(attestation_msg FROM 22), 'UTF8')::jsonb AS body, encode(attestation_sig, 'base64') AS sig FROM mr_spend WHERE store='reh' AND id='a1'")).rows[0];
    log("A1", { result: r, txId: s.txId, fv: s.fv, lv: s.lv, headAtBuild: s.headAtBuild, independentIndexerStatus: idx.status, row, audit, attestation: att ?? null, cliPages: pages });
    expect(r.ok).toBe(true);
    expect(row.status).toBe("released");
    expect(idx.status).toBe(404);
  }, 120_000);

  it("A4: restoring an old policy.json refuses to boot; a 6th release in 24 h is refused by the DB", async () => {
    stop(main);
    const cur = readFileSync(path.join(dir, "policy.json"));
    copyFileSync(policySnapshot, path.join(dir, "policy.json"));
    const e = await boot().then(() => null, (x: Error) => x);
    writeFileSync(path.join(dir, "policy.json"), cur);
    main = await boot();
    // 4 synthetic nonce rows (labeled) so that the next release is the 6th in 24 h
    const keyId = f.signer.keyId;
    // HARNESS ONLY (local test DB, table owner, inside one transaction): the guard admits owner writes only with
    // the definer flag set; the app/release roles can't do this.
    const c = await own.connect();
    try {
      await c.query("BEGIN");
      await c.query("SELECT set_config('mr.spend_fn', 'on', true)");
      for (let i = 0; i < 4; i++) await c.query("INSERT INTO mr_release_nonce (nonce, store, spend_id, key_id) VALUES ($1, 'reh-synthetic', $2, $3)", [randomBytes(32), `synthetic-${i}`, keyId]);
      await c.query("COMMIT");
    } finally { c.release(); }
    const n = Number((await own.query("SELECT count(*) FROM mr_release_nonce WHERE used_at > clock_timestamp() - interval '24 hours'")).rows[0].count);
    await newAmbiguousSpend("reh", "a4");
    const e6 = await attestedRelease(cliDeps(async () => {}) as never, "reh", "a4").then(() => null, (x: Error) => x);
    const row = (await own.query("SELECT status FROM mr_spend WHERE store='reh' AND id='a4'")).rows[0];
    log("A4", { rollbackBoot: { refused: e instanceof RollbackDetected, error: e?.message }, noncesIn24hBefore6th: n, syntheticNonceRows: 4, sixth: { refused: !!e6, error: e6?.message?.slice(0, 200) }, rowAfter: row });
    expect(e).toBeInstanceOf(RollbackDetected);
    expect(e6?.message).toMatch(/limit of 5 attested releases per 24 h/);
    expect(row.status).toBe("ambiguous");
  }, 120_000);

  it("A2: forged, replayed and stale confirms are refused (signer and helper); three misses lock the helper", async () => {
    const t = transport();
    const forger = edKey();
    const s = await newAmbiguousSpend("reh", "a2");
    void s;
    const out: Record<string, string> = {};
    const tryC = async (k: string, q: SignedRequest) => { try { await t.confirm(q); out[k] = "ACCEPTED"; } catch (e) { out[k] = (e as Error).message; } };
    await tryC("signer.forged", reqBody(forger.priv, { op: "confirm", store: "reh", spendId: "a2", msgHash: "00".repeat(32) }));
    await tryC("signer.replayed", sentConfirms[0]!);
    await tryC("signer.stale", reqBody(requester.priv, { op: "confirm", store: "reh", spendId: "a2", msgHash: "00".repeat(32) }, Date.now() - 120_000));
    const hc = new HelperSocketClient(helperSock);
    const tryH = async (k: string, q: SignedRequest) => { try { await hc.sign(new Uint8Array(8), q); out[k] = "SIGNED"; } catch (e) { out[k] = (e as Error).message; } };
    await tryH("helper.forged", reqBody(forger.priv, { op: "confirm", store: "reh", spendId: "a2", msgHash: "00".repeat(32) }));
    await tryH("helper.replayed", sentConfirms[0]!);
    await tryH("helper.stale", reqBody(requester.priv, { op: "confirm", store: "reh", spendId: "a2", msgHash: "00".repeat(32) }, Date.now() - 120_000));
    await tryH("helper.afterThreeMisses", reqBody(requester.priv, { op: "confirm", store: "reh", spendId: "a2", msgHash: "00".repeat(32) }));
    log("A2", { ...out, helperStatus: helper.status(), signerPaused: (main.signer as unknown as { d: { policy: { paused(): { reason: string } | null } } }).d.policy.paused() });
    for (const k of ["signer.forged", "signer.replayed", "signer.stale"]) expect(out[k]).toMatch(/403/);
    for (const k of ["helper.forged", "helper.replayed", "helper.stale"]) expect(out[k]).toMatch(/helper refused: confirm/);
    expect(out["helper.afterThreeMisses"]).toMatch(/locked/);
  }, 120_000);

  it("A6 (rev 21): three lockouts in an hour long-lock the helper for 6 h; no unlock route exists; the lock clears by itself", async () => {
    const hc = new HelperSocketClient(helperSock);
    const forger = edKey();
    for (const adv of [11, 22]) {
      skewMs = adv * 60_000;
      for (let i = 0; i < 3; i++) await hc.sign(new Uint8Array(8), reqBody(forger.priv, { op: "confirm", store: "reh", spendId: "x", msgHash: "00".repeat(32) }, Date.now() + skewMs)).catch(() => {});
    }
    const hard = helper.status();
    const refusedWhileHard = await hc.sign(new Uint8Array(8), reqBody(requester.priv, { op: "confirm", store: "reh", spendId: "x", msgHash: "00".repeat(32) }, Date.now() + skewMs)).then(() => "SIGNED", (e: Error) => e.message);
    const port = (main.server.address() as { port: number }).port;
    const unlockStatus = (await fetch(`http://127.0.0.1:${port}/v1/unlock`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" })).status;
    skewMs += 6 * 3_600_000 + 60_000;
    const after = helper.status();
    const afterSign = await hc.sign(new Uint8Array(8), reqBody(requester.priv, { op: "confirm", store: "reh", spendId: "x", msgHash: "00".repeat(32) }, Date.now() + skewMs)).then(() => "SIGNED", (e: Error) => e.message);
    log("A6", { hardStatus: hard, refusedWhileHard, unlockRouteStatus: unlockStatus, statusAfter6h: after, signAttemptAfter6h: afterSign.slice(0, 120) });
    expect(hard.hard).toBe(true);
    expect(refusedWhileHard).toMatch(/long-locked/);
    expect(unlockStatus).toBe(404);
    expect(after.locked).toBe(false);
    expect(afterSign).not.toMatch(/locked/);
  }, 180_000);

  it("A5: unreachable pager: heartbeat fails with no ping, the signature is withheld and the signer pauses; then a real publish", async () => {
    stop(main);
    const before = pings;
    main = await boot({ ntfyServer: "http://127.0.0.1:9" });
    await sleep(1500);
    const hb = [...main.heartbeats];
    await newAmbiguousSpend("reh", "a5");
    const e = await attestedRelease(cliDeps(async () => {}) as never, "reh", "a5").then(() => null, (x: Error) => x);
    const paused = (main.signer as unknown as { d: { policy: { paused(): { reason: string } | null } } }).d.policy.paused();
    const lines = readFileSync(path.join(dir, "audit.jsonl"), "utf8").split("\n").filter((l) => l.includes("reh/a5"));
    const row = (await own.query("SELECT status FROM mr_spend WHERE store='reh' AND id='a5'")).rows[0];
    const realPage = ntfyPager({ topic: process.env.MR_NTFY_TOPIC! });
    const pub2 = await realPage("[signer TESTNET rehearsal] A5 test publish", `R44 rehearsal ${new Date().toISOString()}: pager restored after the unreachable-pager drill`).then(() => "delivered (HTTP 200)", (x: Error) => x.message);
    log("A5", { heartbeatsWithUnreachablePager: hb, pingsDuringOutage: pings - before, release: e?.message ?? "RELEASED (unexpected)", signerPaused: paused, a5AuditKinds: lines.map((l) => JSON.parse(l.split("\t")[0]!).kind), rowAfter: row, realTestPublish: pub2 });
    expect(hb).toEqual([false]);
    expect(pings - before).toBe(0);
    expect(e).not.toBeNull();
    expect(paused?.reason).toMatch(/page failed/);
    expect(row.status).toBe("ambiguous");
    expect(pub2).toMatch(/delivered/);
    const boots = readFileSync(path.join(dir, "audit.jsonl"), "utf8").split("\n").filter((l) => l.includes('"kind":"boot"')).map((l) => JSON.parse(l.split("\t")[0]!));
    log("helperAnchorAcrossRestarts", boots.map((b) => ({ seq: b.seq, counters: b.counters })));
    expect(boots.slice(1).every((b) => typeof b.counters.helper === "number")).toBe(true);
  }, 120_000);

  it("A7: a REAL submitted-and-confirmed TestNet payment (third-party, rebuilt byte-exact from the indexer) is detected: refused + paused", async () => {
    // a recent single USDC axfer <= 0.01, no group/lease/rekey/close, ed25519-signed (the kind the app stores)
    let found: Record<string, any> | null = null, next = "";
    const head = Number((await json(`${ALGOD}/v2/status`))["last-round"]);
    for (let pg = 0; pg < 60 && !found; pg++) {
      const r = await json(`${IDX}/v2/transactions?asset-id=10458941&tx-type=axfer&currency-less-than=10001&currency-greater-than=0&min-round=${head - 20_000_000}&limit=500${next ? `&next=${next}` : ""}`);
      found = (r.transactions as Record<string, any>[]).find((t) => !t.group && t.signature?.sig && !t["rekey-to"] && !t.lease && t.fee <= 1000
        && t["asset-transfer-transaction"] && !t["asset-transfer-transaction"]["close-to"]) ?? null;
      next = String(r["next-token"] ?? ""); if (!next) break;
    }
    expect(found).not.toBeNull();
    const x = found!, ax = x["asset-transfer-transaction"];
    const t = algosdk.makeAssetTransferTxnWithSuggestedParamsFromObject({ sender: x.sender, receiver: ax.receiver, amount: BigInt(ax.amount), assetIndex: 10458941,
      note: x.note ? new Uint8Array(Buffer.from(x.note, "base64")) : undefined,
      suggestedParams: { fee: BigInt(x.fee), minFee: 1000n, flatFee: true, firstValid: BigInt(x["first-valid"]), lastValid: BigInt(x["last-valid"]), genesisHash: Buffer.from(TN, "base64"), genesisID: x["genesis-id"] } } as never);
    expect(t.txID()).toBe(x.id); // byte-exact rebuild of the submitted transaction
    const bytes = algosdk.encodeMsgpack(new algosdk.SignedTransaction({ txn: t, sig: new Uint8Array(Buffer.from(x.signature.sig, "base64")) }));
    // a second signer instance pinned to that payment's payer/merchant (fresh state, same stand-in labels)
    const d7 = mkdtempSync(path.join(tmpdir(), "mr-reh-a7-"));
    const f7: MainConfigFile = { ...f, stateDir: d7, signer: { ...f.signer, payer: x.sender, merchant: ax.receiver }, audit: { kind: "testnet-standin", minSeq: 0, label: STANDIN_LABEL, file: path.join(d7, "audit.jsonl") } };
    const m7 = await startMain(f7, { MR_NTFY_TOPIC: process.env.MR_NTFY_TOPIC }, { clock, ping: async () => {} });
    try {
      const sp = new PgSpendStore(own, { store: "reh7" });
      await sp.reserve({ id: "a7", payer: x.sender, amountMicro: BigInt(ax.amount), caps: { perPaymentMicro: toMicro("1"), perDayMicro: toMicro("5") }, nowMs: Date.now() });
      expect(await sp.attachSignedTxn("a7", { signedTxn: bytes, kind: "xpayment", payer: x.sender, submitRound: x["last-valid"] - 1, nowMs: Date.now() } as never)).not.toBeNull();
      await sp.finalize("a7", "ambiguous", Date.now());
      await sleep(3500);
      const saved = main; main = m7;
      const e = await attestedRelease(cliDeps(async () => {}) as never, "reh7", "a7").then(() => null, (z: Error) => z);
      main = saved;
      const idx = new HttpProbe({ host: "testnet-idx.4160.nodely.dev", operator: OP_A, kind: "indexer", baseUrl: IDX });
      const alg = new HttpProbe({ host: "testnet-api.algonode.cloud", operator: OP_B, kind: "algod", baseUrl: "https://testnet-api.algonode.cloud" });
      const probes = { indexer: await idx.probe([x.id], x["first-valid"], x["last-valid"]), algodBlockscan: await alg.probe([x.id], x["first-valid"], x["last-valid"]) };
      const lines = readFileSync(path.join(d7, "audit.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l.split("\t")[0]!));
      const paused = (m7.signer as unknown as { d: { policy: { paused(): { reason: string } | null } } }).d.policy.paused();
      const row = (await own.query("SELECT status FROM mr_spend WHERE store='reh7' AND id='a7'")).rows[0];
      proof.auditLogA7 = lines; // R46: A7's own audit chain (boot, refusal/anomaly), separate instance
      log("A7", { txId: x.id, confirmedRound: x["confirmed-round"], fv: x["first-valid"], lv: x["last-valid"], roundTime: new Date(x["round-time"] * 1000).toISOString(),
        rebuiltTxIdMatches: t.txID() === x.id, release: e?.message ?? "RELEASED (unexpected)", probes, signerPaused: paused,
        auditKinds: lines.map((l) => `${l.kind}${l.reason ? `: ${String(l.reason).slice(0, 90)}` : ""}`), rowAfter: row,
        limits: "third-party payment (our own submitted payment is A7-own); submit_round = lv-1 as in A1 (the real submit predates the row)" });
      expect(e).not.toBeNull();
      expect(probes.indexer.kind).toBe("present");
      expect(paused?.reason).toMatch(/anomaly: .*present/);
      expect(row.status).toBe("ambiguous");
    } finally { stop(m7); }
  }, 180_000);

  // R46: A7-own: OUR OWN payment, submitted by us on TestNet from the e2e:paid payer, then detected.
  const OWN_MN = process.env.MR_TN_PAYER_MNEMONIC_FILE, OWN_ADDR = process.env.MR_TN_PAYER_ADDRESS, OWN_MERCHANT = process.env.MR_TN_MERCHANT_ADDRESS;
  it.skipIf(!OWN_MN || !OWN_ADDR || !OWN_MERCHANT)("A7-own: our own TestNet USDC payment, stored as the app would, then submitted and confirmed, is detected: refused + paused", async () => {
    const acct = algosdk.mnemonicToSecretKey(readFileSync(OWN_MN!, "utf8").trim()); // never printed
    expect(acct.addr.toString()).toBe(OWN_ADDR);
    const params = await json(`${ALGOD}/v2/transactions/params`);
    expect(params["genesis-hash"]).toBe(TN); // TestNet only
    const R = Number(params["last-round"]), fv = R, lv = R + 12;
    const t = algosdk.makeAssetTransferTxnWithSuggestedParamsFromObject({ sender: OWN_ADDR!, receiver: OWN_MERCHANT!, amount: 1000n, assetIndex: 10458941,
      note: new Uint8Array(Buffer.from(`mandaterail R46 rehearsal A7-own ${new Date().toISOString()}`)),
      suggestedParams: { fee: 1000n, minFee: 1000n, flatFee: true, firstValid: BigInt(fv), lastValid: BigInt(lv), genesisHash: Buffer.from(TN, "base64"), genesisID: "testnet-v1.0" } } as never);
    const bytes = t.signTxn(acct.sk);
    const d8 = mkdtempSync(path.join(tmpdir(), "mr-reh-a7own-"));
    const f8: MainConfigFile = { ...f, stateDir: d8, signer: { ...f.signer, payer: OWN_ADDR!, merchant: OWN_MERCHANT! }, audit: { kind: "testnet-standin", minSeq: 0, label: STANDIN_LABEL, file: path.join(d8, "audit.jsonl") } };
    const sp = new PgSpendStore(own, { store: "reh8" });
    // the app stores the signed bytes and the submit round BEFORE submitting
    await sp.reserve({ id: "a7own", payer: OWN_ADDR!, amountMicro: 1000n, caps: { perPaymentMicro: toMicro("1"), perDayMicro: toMicro("5") }, nowMs: Date.now() });
    expect(await sp.attachSignedTxn("a7own", { signedTxn: bytes, kind: "xpayment", payer: OWN_ADDR!, submitRound: R, nowMs: Date.now() } as never)).not.toBeNull();
    const submittedAt = new Date().toISOString();
    const sub = await fetch(`${ALGOD}/v2/transactions`, { method: "POST", headers: { "content-type": "application/x-binary" }, body: Buffer.from(bytes) });
    const subBody = (await sub.json()) as Record<string, unknown>;
    expect(sub.status).toBe(200);
    expect(subBody.txId).toBe(t.txID());
    let confirmedRound = 0;
    for (let i = 0; i < 40 && !confirmedRound; i++) {
      await sleep(1500);
      const p = await json(`${ALGOD}/v2/transactions/pending/${t.txID()}`);
      confirmedRound = Number(p["confirmed-round"] ?? 0);
    }
    expect(confirmedRound).toBeGreaterThan(0);
    // the app lost the ack: the row ends up ambiguous
    await sp.finalize("a7own", "ambiguous", Date.now());
    // REAL timing (no lv-1 shortcut): wait until head > lv + margin and the submit-time lv estimate has passed
    for (;;) { const h = Number((await json(`${ALGOD}/v2/status`))["last-round"]); if (h > lv + 10 + 2) break; await sleep(3000); }
    await sleep(Math.max(0, Date.parse(submittedAt) + 12 * 2500 + 2000 - Date.now()));
    const m8 = await startMain(f8, { MR_NTFY_TOPIC: process.env.MR_NTFY_TOPIC }, { clock, ping: async () => {} });
    try {
      const saved = main; main = m8;
      const e = await attestedRelease(cliDeps(async () => {}) as never, "reh8", "a7own").then(() => null, (z: Error) => z);
      main = saved;
      const idx = new HttpProbe({ host: "testnet-idx.4160.nodely.dev", operator: OP_A, kind: "indexer", baseUrl: IDX });
      const alg = new HttpProbe({ host: "testnet-api.algonode.cloud", operator: OP_B, kind: "algod", baseUrl: "https://testnet-api.algonode.cloud" });
      const probes = { indexer: await idx.probe([t.txID()], fv, lv), algodBlockscan: await alg.probe([t.txID()], fv, lv) };
      const lines = readFileSync(path.join(d8, "audit.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l.split("\t")[0]!));
      const paused = (m8.signer as unknown as { d: { policy: { paused(): { reason: string } | null } } }).d.policy.paused();
      const row = (await own.query("SELECT status, submit_round FROM mr_spend WHERE store='reh8' AND id='a7own'")).rows[0];
      proof.auditLogA7own = lines;
      log("A7own", { txId: t.txID(), payer: OWN_ADDR, merchant: OWN_MERCHANT, amountMicroUsdc: 1000, fv, lv, submitRoundStored: R, submittedAt, submitHttp: sub.status, confirmedRound,
        release: e?.message ?? "RELEASED (unexpected)", probes, signerPaused: paused, rowAfter: row,
        limits: "confirmed case only: public TestNet confirms a valid submitted txn within a round, so a submitted-then-expired txn cannot be forced honestly (the never-submitted expiry is A1)" });
      expect(e).not.toBeNull();
      expect(probes.indexer.kind).toBe("present");
      expect(paused?.reason).toMatch(/anomaly: .*present/);
      expect(row.status).toBe("ambiguous");
    } finally { stop(m8); }
  }, 300_000);
});
void createHash;

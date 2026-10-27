import { createHash } from "node:crypto";
/**
 * mr-signer entrypoint (R44-GATE-1): config -> off-host audit chain (B2 Object Lock; TestNet may use the
 * labeled stand-in) -> boot gate (counters, minSeq) -> HTTP server on the WireGuard address -> heartbeat timer
 * (self-check incl. a real ntfy test publish, then the dead-man ping).
 *
 * Config: MR_SIGNER_CONFIG (JSON, no secrets). Secrets come only from the environment (systemd
 * EnvironmentFile, 0600): MR_NTFY_TOPIC, MR_HC_PING_URL (optional until a Healthchecks account exists),
 * MR_B2_KEY_ID, MR_B2_APP_KEY. None of them is ever logged.
 */
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import type { Server } from "node:http";
import { assertConfigFileModeForProviders, probeScanOpts, GENESIS_PINS, validateConfig, type Network, type PinnedProvider, type SignerConfig } from "./config.js";
import { ChainedAudit, heartbeat, type AuditSink, type Pager } from "./audit.js";
import { chronySource, type ClockSource } from "./clock.js";
import { DurableJson } from "./state.js";
import { initialPolicyState, PolicyEngine, type PolicyState } from "./policy.js";
import { initialReqState, RequestAuth, type ReqState } from "./requests.js";
import { HttpProbe, type ChainProbe } from "./providers.js";
import { assertEscrowProviders, EscrowRuntime, HttpEscrowReader, initialEscrowState, type EscrowLocalState, type EscrowReader } from "./escrow-release.js";
import { MrSigner, type HelperLike } from "./signer.js";
import { signerServer } from "./server.js";
import { HelperSocketClient } from "./piv/socket.js";
import { B2ObjectLockSink } from "./sinks/s3.js";
import { STANDIN_LABEL } from "./sinks/labels.js";
import { deadManPing, ntfyPager, startHeartbeat } from "./pager.js";

export interface MainConfigFile {
  signer: Omit<SignerConfig, "requesters" | "feePayerMaxFee" | "payerMaxFee" | "policy"> & {
    requesters: { id: string; pubkeyB64: string }[]; feePayerMaxFee: string; payerMaxFee: string;
    policy: Omit<SignerConfig["policy"], "maxAmountMicro" | "maxReleasedMicroPerDay"> & { maxAmountMicro: string; maxReleasedMicroPerDay: string };
  };
  attestPubkeyB64: string; // pinned attestation public key (self-verify)
  /** rev 21: mr-verifier's pinned public key, for its resume co-signature (required on MainNet). No unlock key exists. */
  cosignerPubkeyB64?: string;
  stateDir: string;
  helperSocket: string;
  listen: { host: string; port: number; allowIps: string[] };
  audit: { kind: "b2"; minSeq: number; b2: { endpoint: string; region: string; bucket: string; prefix: string; retainDays: number } }
       | { kind: "testnet-standin"; minSeq: number; label: string; file: string };
  heartbeatIntervalS: number;
  ntfyServer?: string;
  /** escrow release path (design rev 6): app id and the pinned epochs; readers are the pinned algod providers */
  /** R76-P3-1/2: `operators` = the escrow operator allowlist (required); it is also the pinned list for pending-abandon judgments */
  escrow?: { appId: string; keyEpoch: string; configEpoch: string; operators: string[] };
}

/** R76-P3-5: a decimal u64 string; BigInt("") / BigInt(" 1") / "0x.." are refused (BigInt("") would be 0n). */
export function parseU64(v: unknown, name: string): bigint {
  if (typeof v !== "string" || !/^(0|[1-9][0-9]{0,19})$/.test(v)) throw new Error(`${name} must be a decimal u64 string`);
  const b = BigInt(v);
  if (b > 0xffff_ffff_ffff_ffffn) throw new Error(`${name} out of u64 range`);
  return b;
}

/** sha256 of the canonical (sorted-key) config JSON. Holds no secrets (secrets are env / credential files). */
export function configSha256(f: MainConfigFile): string {
  const sort = (v: unknown): unknown => Array.isArray(v) ? v.map(sort) : v && typeof v === "object" ? Object.fromEntries(Object.keys(v as object).sort().map((k) => [k, sort((v as Record<string, unknown>)[k])])) : v;
  return createHash("sha256").update(JSON.stringify(sort(f))).digest("hex");
}

export function parseSignerConfig(f: MainConfigFile): SignerConfig {
  const s = f.signer;
  return validateConfig({
    ...s, providers: s.providers as PinnedProvider[], feePayerMaxFee: BigInt(s.feePayerMaxFee), payerMaxFee: BigInt(s.payerMaxFee),
    requesters: s.requesters.map((r) => ({ id: r.id, pubkey: new Uint8Array(Buffer.from(r.pubkeyB64, "base64")) })),
    policy: { ...s.policy, maxAmountMicro: BigInt(s.policy.maxAmountMicro), maxReleasedMicroPerDay: BigInt(s.policy.maxReleasedMicroPerDay) },
  });
}


export async function buildSink(f: MainConfigFile, env: NodeJS.ProcessEnv): Promise<AuditSink> {
  if (f.audit.kind === "b2") {
    const keyId = env.MR_B2_KEY_ID, appKey = env.MR_B2_APP_KEY;
    if (!keyId || !appKey) throw new Error("MR_B2_KEY_ID / MR_B2_APP_KEY not set");
    return new B2ObjectLockSink({ ...f.audit.b2, accessKeyId: keyId, secretAccessKey: appKey });
  }
  if (f.signer.network !== "testnet") throw new Error("the stand-in sink is TESTNET-ONLY");
  // R45-P3-1: loaded only on TestNet; the module is excluded from the MainNet image (deploy/signer/mainnet-image.exclude)
  const { LocalAppendStandInSink } = await import("./sinks/local-standin.js");
  return new LocalAppendStandInSink(f.audit.file, { network: f.signer.network, label: f.audit.label });
}

export interface Running { signer: MrSigner; audit: ChainedAudit; server: Server; stopHeartbeat: () => void; heartbeats: boolean[] }

export async function startMain(f: MainConfigFile, env: NodeJS.ProcessEnv, o: { sink?: AuditSink; pager?: Pager; ping?: () => Promise<void>; clock?: ClockSource; probes?: ChainProbe[]; helper?: HelperLike; escrowReaders?: EscrowReader[] } = {}): Promise<Running> {
  const cfg = parseSignerConfig(f);
  if (GENESIS_PINS[cfg.network as Network] !== cfg.genesisHash) throw new Error("genesis pin");
  if (!env.MR_NTFY_TOPIC && !o.pager) throw new Error("MR_NTFY_TOPIC not set");
  const pager = o.pager ?? ntfyPager({ topic: env.MR_NTFY_TOPIC!, server: f.ntfyServer });
  const audit = await ChainedAudit.open(o.sink ?? (await buildSink(f, env)), pager, { minSeq: f.audit.minSeq });
  const pj = path.join(f.stateDir, "policy.json"), rj = path.join(f.stateDir, "requests.json");
  // first install only: missing state with a non-empty off-host log is a wipe, not a fresh start
  for (const [file, init] of [[pj, initialPolicyState()], [rj, initialReqState()]] as const) {
    if (!existsSync(file)) {
      if (audit.headSeq() > 0) throw new Error(`${path.basename(file)} is missing but the off-host log has ${audit.headSeq()} events: wiped`);
      DurableJson.init(file, init as never);
    }
  }
  let escrow: EscrowRuntime | undefined;
  if (f.escrow) {
    const ej = path.join(f.stateDir, "escrow.json");
    // a lost escrow.json would forget a pending abandon: same wipe rule as policy/requests (fail closed)
    if (!existsSync(ej)) {
      if (audit.headSeq() > 0) throw new Error("escrow.json is missing but the off-host log has events: wiped (init it explicitly after review)");
      DurableJson.init(ej, initialEscrowState());
    }
    const readers = o.escrowReaders ?? cfg.providers.filter((p) => p.kind !== "indexer").map((p) => new HttpEscrowReader(p));
    if (new Set(readers.map((r) => r.provider)).size < 2) throw new Error("escrow needs algod providers from >= 2 operators");
    assertEscrowProviders(readers, f.escrow.operators, cfg.network);
    escrow = new EscrowRuntime({ readers, appId: parseU64(f.escrow.appId, "escrow.appId"), genesisB64: cfg.genesisHash,
      pins: { keyEpoch: parseU64(f.escrow.keyEpoch, "escrow.keyEpoch"), configEpoch: parseU64(f.escrow.configEpoch, "escrow.configEpoch"), operators: [...f.escrow.operators] },
      store: new DurableJson<EscrowLocalState>(ej) });
  }
  const policy = new PolicyEngine(cfg.policy, new DurableJson<PolicyState>(pj));
  const auth = new RequestAuth(cfg.requesters, new DurableJson<ReqState>(rj), { maxAgeS: cfg.requestMaxAgeS, ratePerHour: cfg.requesterRatePerHour, network: cfg.network });
  const pub = new Uint8Array(Buffer.from(f.attestPubkeyB64, "base64"));
  const cosignerPubkey = f.cosignerPubkeyB64 ? new Uint8Array(Buffer.from(f.cosignerPubkeyB64, "base64")) : undefined;
  if (cosignerPubkey && cosignerPubkey.length !== 32) throw new Error("cosignerPubkeyB64 must be a 32-byte Ed25519 key");
  if (!cosignerPubkey && cfg.network === "mainnet") throw new Error("MainNet requires cosignerPubkeyB64 (resume quorum, rev 21)");
  if (cosignerPubkey && Buffer.from(cosignerPubkey).equals(Buffer.from(pub))) throw new Error("cosignerPubkeyB64 must differ from the attestation key");
  const signer = MrSigner.boot({
    cosignerPubkey, escrow,
    cfg, auth, policy, audit, clock: o.clock ?? chronySource,
    probes: o.probes ?? cfg.providers.map((p) => new HttpProbe(p, undefined, undefined, process.env, probeScanOpts(cfg))),
    helper: o.helper ?? new HelperSocketClient(f.helperSocket),
    backend: { publicKey: async () => pub },
  });
  // the boot line carries the helper counter forward, so the anchor survives restarts (R44 rehearsal finding)
  const hc = audit.helperCounter();
  // rev 21: config changes happen only by redeploy; every boot records the config hash in the B2 chain (and pages)
  await audit.log({ kind: "boot", reason: `config sha256 ${configSha256(f)}`, at: Date.now(), counters: { policy: policy.counter(), requests: auth.counter(), ...(hc !== undefined ? { helper: hc } : {}) } });
  const server = signerServer(signer, { allowIps: f.listen.allowIps });
  await new Promise<void>((r) => server.listen(f.listen.port, f.listen.host, r));
  const ping = o.ping ?? deadManPing(env.MR_HC_PING_URL ?? null);
  const heartbeats: boolean[] = [];
  const stopHeartbeat = startHeartbeat(() => heartbeat(() => signer.selfCheck(), ping), f.heartbeatIntervalS * 1000, (ok) => heartbeats.push(ok));
  return { signer, audit, server, stopHeartbeat, heartbeats };
}

if (process.argv[1] && /main\.(ts|js)$/.test(process.argv[1]) && process.env.MR_SIGNER_CONFIG) {
  const f = JSON.parse(readFileSync(process.env.MR_SIGNER_CONFIG, "utf8")) as MainConfigFile;
  assertConfigFileModeForProviders(process.env.MR_SIGNER_CONFIG, (f.signer?.providers ?? []) as PinnedProvider[]); // R54-P3-4
  if (f.audit.kind !== "b2" && f.audit.label !== STANDIN_LABEL) throw new Error("stand-in sink must carry its label");
  startMain(f, process.env).then(
    (r) => { process.stdout.write(`mr-signer up on ${f.listen.host}:${f.listen.port} (audit head seq ${r.audit.headSeq()})\n`); },
    (e) => { process.stderr.write(`mr-signer refused to start: ${(e as Error).message}\n`); process.exit(1); },
  );
}

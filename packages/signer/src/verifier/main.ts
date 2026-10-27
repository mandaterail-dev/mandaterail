/**
 * mr-verifier entrypoint (v12 §15). Config: MR_VERIFIER_CONFIG (JSON; no secrets unless a provider baseUrl has a path token, then 0600 is enforced; Blockdaemon keys come from env via apiKeyEnv); env: MR_NTFY_TOPIC (its own
 * topic), MR_HC_PING_URL. Key (R75-P2-1, docs/ops/kms-key-order.md): on MainNet ONLY the manifest-gated aliyun-softkey;
 * awskms / ykcs11 / cloudkms are refused there (the AWS and GCP KMS keys are locked backups). TestNet may also use
 * awskms / ykcs11 (never a backup key) or the software key.
 */
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { chronySource } from "../clock.js";
import { DurableJson } from "../state.js";
import { HttpProbe } from "../providers.js";
import { initialReqState, RequestAuth, type ReqState } from "../requests.js";
import { deadManPing, ntfyPager, startHeartbeat } from "../pager.js";
import { parseSignerConfig, type MainConfigFile } from "../main.js";
import { assertConfigFileModeForProviders, ConfigError, probeScanOpts, validatePinnedProvider } from "../config.js";
import type { SignBackend } from "../piv/backend.js";
import { AwsKmsBackend, type AwsKmsOptions } from "../piv/awskms.js";
import { ACTIVE_COSIGNER, loadKeyOrder } from "../piv/key-order.js";
import { loadPkcs11js, YubikeyPkcs11Backend, type YkcsOptions } from "../piv/ykcs11.js";
import { initialVerifierState, SecondVerifier, type VerifierState } from "./verifier.js";
import { verifierServer } from "./server.js";
import { B2ObjectLockSink, type S3SinkConfig } from "../sinks/s3.js";
import { verifyChainHead, resumeAppliedAfter, checkForwarderHeartbeat, gcpLoggingSource, initialReconcileState, ntfyHeartbeatSource, Reconciler, type ReconcileState } from "./reconcile.js";

export interface VerifierFile {
  signer: MainConfigFile["signer"]; // shared pins; keyId = the PRIMARY signer's key id
  primaryPubkeyB64: string;
  cosignerPubkeyB64: string;
  providers: { host: string; operator: string; kind: "indexer" | "algod" | "blockscan-full"; baseUrl: string; apiKeyEnv?: string }[];
  ykcs11?: Omit<YkcsOptions, "pubkey" | "network">;
  /** R48-P2-1: the recommended MainNet key, outside Google */
  awskms?: Omit<AwsKmsOptions, "pubkey" | "network">;
  /**
   * R49-P2-1/2: reconcile Cloud KMS AsymmetricSign audit entries with the signer's off-host chain, and watch the
   * GCP alert forwarder heartbeat. Secrets in env only: MR_GCP_TOKEN_FILE (an access token for a read-only
   * logging viewer, refreshed by a timer via Workload Identity Federation from the verifier's AWS role; no GCP key
   * file), MR_B2_READ_KEY_ID / MR_B2_READ_APP_KEY (read-only B2 key), MR_FWD_NTFY_TOPIC (forwarder topic).
   */
  reconcile?: { project: string; keyVersion: string; signerSa: string; signerIp: string; signerNetwork: string;
    b2: Omit<S3SinkConfig, "accessKeyId" | "secretAccessKey">; intervalS: number; heartbeatMaxAgeH?: number };
  stateDir: string; listen: { host: string; port: number; allowIps: string[] }; heartbeatIntervalS: number;
  /** deploy/verifier/render-platform.sh platform this host was rendered for (§24) */
  platform?: "aliyun" | "aliyun-softkey"; // R76-P3-6: the AWS co-signer platforms (aws, aliyun-aws-kms) were removed
  /**
   * rev 24 (§24.8): the co-signing key as a host-generated Ed25519 file delivered by systemd LoadCredential
   * (platform aliyun-softkey). allowMainnet is the host opt-in; MainNet also needs verifierSoftkey.mainnet = true in
   * the sha256-pinned integrity manifest (false today).
   */
  softkey?: { credentialName?: string; allowMainnet?: boolean };
}

export const KNOWN_PLATFORMS = ["aliyun", "aliyun-softkey"] as const;
/** R76-P3-6: removed AWS co-signer platforms; a config naming one is refused with a clear message. */
export const REMOVED_PLATFORMS = ["aws", "aliyun-aws-kms"] as const;

/** Operators the aliyun-softkey co-signer may pin on MainNet: dRPC only (disjoint from the signer's nodely / getblock). */
export const OPTION_C_MAINNET_OPERATORS = ["drpc"] as const;
/** Verifier platform checks. R76-P3-6: the AWS co-signer platforms (aws, §24 option C aliyun-aws-kms) are removed and refused. */
export function assertPlatformConfig(f: Pick<VerifierFile, "platform" | "awskms" | "ykcs11" | "providers" | "softkey">, sc: { network: string; providers: { operator: string }[] }): void {
  // R67-P3-4 / R76-P3-6: unknown or removed platforms are refused, and so are Roles Anywhere credentials
  if ((REMOVED_PLATFORMS as readonly string[]).includes(String(f.platform))) throw new ConfigError(`verifier platform ${String(f.platform)} was removed (R76-P3-6: no AWS co-signer; the only active co-signer is ${ACTIVE_COSIGNER})`);
  if (f.platform !== undefined && !(KNOWN_PLATFORMS as readonly string[]).includes(f.platform)) throw new ConfigError(`unknown verifier platform ${String(f.platform)}`);
  if ((f.awskms as { credentialSource?: unknown } | undefined)?.credentialSource === "rolesanywhere-serve") throw new ConfigError("awskms.credentialSource rolesanywhere-serve (option C) was removed (R76-P3-6)");
  if (f.softkey && f.platform !== "aliyun-softkey") throw new ConfigError("softkey is only for platform aliyun-softkey");
  if (f.platform === "aliyun-softkey") {
    if (!f.softkey || f.awskms || f.ykcs11) throw new ConfigError("platform aliyun-softkey needs softkey and no awskms / ykcs11");
    assertDrpcOnly(f, sc, "aliyun-softkey");
    return;
  }
  // R75-P2-1: key order (docs/ops/kms-key-order.md): on MainNet the ONLY active co-signer is aliyun-softkey
  if (sc.network === "mainnet") throw new ConfigError(`MainNet verifier: the only active co-signer is ${ACTIVE_COSIGNER} (platform aliyun-softkey); ${f.platform ?? "this platform"} / awskms / ykcs11 are refused (AWS KMS is a locked backup)`);
}

/** MainNet co-signer providers: dRPC only and disjoint from the signer's operators (aliyun-softkey). */
function assertDrpcOnly(f: Pick<VerifierFile, "providers">, sc: { network: string; providers: { operator: string }[] }, platform: string): void {
  if (sc.network !== "mainnet") return;
  const signerOps = new Set(sc.providers.map((p) => p.operator));
  for (const p of f.providers) {
    if (!(OPTION_C_MAINNET_OPERATORS as readonly string[]).includes(p.operator)) throw new ConfigError(`platform ${platform}: MainNet verifier providers are dRPC only (got operator ${p.operator})`);
    if (signerOps.has(p.operator)) throw new ConfigError(`platform ${platform}: operator ${p.operator} is also pinned by the signer`);
  }
}

export async function startVerifier(f: VerifierFile, env: NodeJS.ProcessEnv) {
  const sc = parseSignerConfig({ signer: f.signer } as MainConfigFile);
  for (const p of f.providers) validatePinnedProvider(p);
  assertPlatformConfig(f, sc);
  // v12: the co-signer must have at least one operator the signer does not pin (else every co-sign is refused)
  const signerOps = new Set(sc.providers.map((p) => p.operator));
  if (!f.providers.some((p) => !signerOps.has(p.operator))) throw new ConfigError("verifier needs a provider whose operator the signer does not pin (v12 independence)");
  const pub = new Uint8Array(Buffer.from(f.cosignerPubkeyB64, "base64"));
  let backend: SignBackend;
  if (sc.network === "mainnet") loadKeyOrder("mainnet", env); // R75-P2-1: the key inventory must be present and well formed
  if (f.softkey) {
    const { loadIntegrityManifest } = await import("@mandaterail/storage");
    // the release's own manifest; its sha256 must equal INTEGRITY_MANIFEST_SHA256 (overrides refused on mainnet / production)
    const m = loadIntegrityManifest({ NETWORK: sc.network, NODE_ENV: env.NODE_ENV, MONITOR_INTEGRITY_MANIFEST: env.MONITOR_INTEGRITY_MANIFEST });
    const { SoftkeyFileEd25519Backend } = await import("../piv/softkey-file.js");
    backend = new SoftkeyFileEd25519Backend({ network: sc.network, pubkey: pub, credentialName: f.softkey.credentialName, allowMainnet: f.softkey.allowMainnet,
      manifestAllows: m.verifierSoftkey?.[sc.network] === true }, env);
  } else if (sc.network === "mainnet") throw new ConfigError(`MainNet verifier: the only active co-signer is ${ACTIVE_COSIGNER} (softkey, manifest-gated); awskms / ykcs11 are refused (R75-P2-1)`);
  else if (f.awskms) backend = new AwsKmsBackend({ ...f.awskms, network: sc.network, pubkey: pub });
  else if (f.ykcs11) backend = new YubikeyPkcs11Backend({ ...f.ykcs11, network: sc.network, pubkey: pub }, await loadPkcs11js());
  else if (sc.network === "testnet") backend = new (await import("../piv/backend-software.js")).SoftwareEd25519Backend("testnet");
  else throw new Error("verifier: no key backend configured");
  const vj = path.join(f.stateDir, "verifier.json"), rj = path.join(f.stateDir, "requests.json");
  if (!existsSync(vj)) DurableJson.init<VerifierState>(vj, initialVerifierState());
  if (!existsSync(rj)) DurableJson.init<ReqState>(rj, initialReqState());
  if (!env.MR_NTFY_TOPIC) throw new Error("MR_NTFY_TOPIC not set");
  const page = ntfyPager({ topic: env.MR_NTFY_TOPIC });
  const { keyIdOf } = await import("@mandaterail/storage");
  const v = new SecondVerifier({ signer: sc, primaryPubkey: new Uint8Array(Buffer.from(f.primaryPubkeyB64, "base64")), cosignerKeyId: keyIdOf(await backend.publicKey()),
    providers: f.providers, maxPerHour: 3, maxPer24h: 5, attestTtlS: sc.attestTtlS },
  { auth: new RequestAuth(sc.requesters, new DurableJson<ReqState>(rj), { maxAgeS: sc.requestMaxAgeS, ratePerHour: sc.requesterRatePerHour, network: sc.network }),
    probes: f.providers.map((p) => new HttpProbe(p, undefined, undefined, env, probeScanOpts(sc))), backend, st: new DurableJson<VerifierState>(vj), clock: chronySource, page,
    tamperBaseCooldownS: sc.policy.tamperBaseCooldownS,
    // rev 21: its own resume checks (late-bound: the reconciler is built below; without it, resume is refused)
    resumeChecks: async (seq, head) => {
      if (!recRef || !chainRef) throw new Error("reconcile is not configured: no independent chain check");
      if (recRef.status().open) throw new Error("open KMS/chain mismatch");
      await verifyChainHead(chainRef, seq, head);
    },
    // R62-P3-2: lift its own pause only once the applied resume is in the signer chain
    resumeObservedCheck: async (seq, attestHash) => {
      if (!chainRef) throw new Error("reconcile is not configured: no independent chain check");
      return resumeAppliedAfter(chainRef, seq, attestHash);
    } });
  const st = new DurableJson<VerifierState>(vj);
  const ping = deadManPing(env.MR_HC_PING_URL ?? null);
  const stop = startHeartbeat(async () => {
    // R46-P3: healthy = not paused AND clock synced (same source as requests); the page itself is the test publish
    if (st.get().paused) return false;
    const c = await chronySource().catch(() => null);
    if (!c || !c.synced || Math.abs(c.offsetS) > sc.maxClockSkewS) return false;
    await page("[verifier] heartbeat test", ""); await ping(); return true; }, f.heartbeatIntervalS * 1000);
  let stopRec = () => {};
  let recRef: Reconciler | undefined;
  let chainRef: B2ObjectLockSink | undefined;
  // acks use their own nonce file (same requester keys) so they never share a rate budget with co-sign requests
  let ackAuth: RequestAuth | undefined;
  if (f.reconcile) {
    const r = f.reconcile;
    for (const k of ["MR_GCP_TOKEN_FILE", "MR_B2_READ_KEY_ID", "MR_B2_READ_APP_KEY", "MR_FWD_NTFY_TOPIC"]) if (!env[k]) throw new Error(`reconcile: ${k} not set`);
    const cj = path.join(f.stateDir, "reconcile.json");
    if (!existsSync(cj)) DurableJson.init<ReconcileState>(cj, initialReconcileState(Date.now()));
    const rst = new DurableJson<ReconcileState>(cj);
    const token = async () => readFileSync(env.MR_GCP_TOKEN_FILE!, "utf8").trim();
    chainRef = new B2ObjectLockSink({ ...r.b2, accessKeyId: env.MR_B2_READ_KEY_ID!, secretAccessKey: env.MR_B2_READ_APP_KEY! });
    const rec = new Reconciler({ keyVersion: r.keyVersion, signerSa: r.signerSa, signerIp: r.signerIp, signerNetwork: r.signerNetwork },
      { kms: gcpLoggingSource({ project: r.project, keyVersion: r.keyVersion, token }), page, st: rst, chain: chainRef });
    recRef = rec;
    const aj = path.join(f.stateDir, "ack-requests.json");
    if (!existsSync(aj)) DurableJson.init<ReqState>(aj, initialReqState());
    ackAuth = new RequestAuth(sc.requesters, new DurableJson<ReqState>(aj), { maxAgeS: sc.requestMaxAgeS, ratePerHour: 6, network: sc.network });
    const hb = ntfyHeartbeatSource({ topic: env.MR_FWD_NTFY_TOPIC! });
    let busy = false;
    const t = setInterval(() => {
      if (busy) return; busy = true;
      void (async () => {
        try { await rec.tick(); } catch (e) { await page("[verifier] KMS reconcile ERROR", (e as Error).message).catch(() => {}); }
        try { await checkForwarderHeartbeat({ latest: hb, st: rst, page, maxAgeMs: (r.heartbeatMaxAgeH ?? 26) * 3_600_000 }); } catch { /* paged inside */ }
      })().finally(() => { busy = false; });
    }, r.intervalS * 1000);
    stopRec = () => clearInterval(t);
  }
  const server = verifierServer(v, { allowIps: f.listen.allowIps, reconciler: recRef, auth: ackAuth });
  await new Promise<void>((r) => server.listen(f.listen.port, f.listen.host, r));
  return { server, stop: () => { stop(); stopRec(); } };
}

if (process.argv[1] && /verifier[\\/]main\.(ts|js)$/.test(process.argv[1]) && process.env.MR_VERIFIER_CONFIG) {
  const vf = JSON.parse(readFileSync(process.env.MR_VERIFIER_CONFIG, "utf8")) as VerifierFile;
  assertConfigFileModeForProviders(process.env.MR_VERIFIER_CONFIG, vf.providers ?? []); // R54-P3-4
  startVerifier(vf, process.env).then(
    () => process.stdout.write("mr-verifier up\n"),
    (e) => { process.stderr.write(`mr-verifier refused to start: ${(e as Error).message}\n`); process.exit(1); },
  );
}

import { statSync } from "node:fs";
import path from "node:path";
import { urlHasPathToken, X_API_KEY_PROVIDER_HOSTS } from "@mandaterail/core";
/**
 * mr-signer pins (docs/ops/attested-release-signer.md §2, rev 10 §13). One instance serves exactly one network.
 * Nothing here is secret: keys live in the PIV backend; requester keys are public keys.
 */
export const GENESIS_PINS = Object.freeze({
  mainnet: "wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=",
  testnet: "SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=",
});
export type Network = keyof typeof GENESIS_PINS;

export interface PinnedProvider {
  host: string; // lower-case host, no port (must be in the network's provider allowlist)
  operator: string; // operator id (Nodely and algonode.cloud are ONE operator)
  /** blockscan-full: algod whose /v2/blocks/{r}/txids is unavailable (dRPC free); txids are computed from msgpack blocks */
  kind: "indexer" | "algod" | "blockscan-full";
  baseUrl: string; // https://host[/prefix] (GetBlock: https://host/<token> -> the config file is a secret, 0600)
  /** Blockdaemon: the NAME of the env var holding the API key (sent as X-API-Key), e.g. "BLOCKDAEMON_API_KEY". Never the key. */
  apiKeyEnv?: string;
}

/**
 * R54-P3-4: a config whose provider baseUrl carries a path token is a secret: refuse to start unless the file is
 * owner-only (no group/other bits). Configs without path tokens are not secrets and are not checked.
 */
export function assertConfigFileModeForProviders(file: string, providers: ReadonlyArray<{ baseUrl: string }>, statImpl: (f: string) => { mode: number } = statSync): void {
  if (!providers.some((p) => urlHasPathToken(p.baseUrl))) return;
  const mode = statImpl(file).mode & 0o777;
  if (mode & 0o077) throw new ConfigError(`config ${path.basename(file)} holds a provider URL with a path token; chmod 0600 (mode is ${mode.toString(8)})`);
}

export interface PolicyConfig {
  /** max USDC micro per released spend (a false release frees at most one payment: 0.01 USDC = 10000). */
  maxAmountMicro: bigint;
  maxReleasesPerHour: number;
  maxReleasesPerDay: number;
  maxReleasedMicroPerDay: bigint;
  /** UTC hours [from, to) during which signing is allowed; [0, 24) = always. */
  windowUtcHours: [number, number];
  /** refusals (any reason) within one hour that auto-pause the signer. */
  anomalyPauseRefusalsPerHour: number;
  /** rev 21: tamper-pause cooldown base (s); doubles per tamper. MainNet floor 6 h. */
  tamperBaseCooldownS?: number;
}

export interface SignerConfig {
  network: Network;
  genesisHash: string;
  margin: number; // rounds; equals the DB key row margin
  usdcAsaId: number;
  payer: string; // pinned sender (snd)
  merchant: string; // pinned receiver (arcv)
  feePayer: string | null; // pinned fee-payer for groups (GoPlausible pattern)
  feePayerMaxFee: bigint; // µALGO
  payerMaxFee: bigint; // µALGO, single-member xpayment (the payer pays its own fee)
  keyId: string; // the pinned attestation key id (32 hex)
  providers: PinnedProvider[];
  requesters: { id: string; pubkey: Uint8Array }[]; // pinned requester keys (Ed25519 raw 32 bytes)
  requesterRatePerHour: number;
  requestMaxAgeS: number; // signed request timestamp window
  maxClockSkewS: number; // chrony |offset| bound (R42-P3-1: refuse above ~5 s)
  maxSnapshotAgeS: number; // DB snapshot staleness bound (R42-P3-1)
  maxHeadSpreadRounds: number; // provider head disagreement bound (stale provider)
  attestTtlS: number; // expiry - now (<= 900; MainNet >= 600, R59-P3-1)
  /** R59-P3-2: block-scan limits for HttpProbe (default 240 s / 4 in flight). deadlineS in [30, 240], concurrency 1..8. */
  scan?: { deadlineS?: number; concurrency?: number };
  policy: PolicyConfig;
}

export class ConfigError extends Error {}

/** R59-P3-2: HttpProbe scan options from the config (undefined = defaults: 240 s, 4). */
export function probeScanOpts(c: Pick<SignerConfig, "scan">): { deadlineMs?: number; concurrency?: number } {
  return { deadlineMs: c.scan?.deadlineS !== undefined ? c.scan.deadlineS * 1000 : undefined, concurrency: c.scan?.concurrency };
}

/** Validates one pinned provider's URL / auth fields (shared by the signer and the verifier). */
export function validatePinnedProvider(p: PinnedProvider): void {
  const u = new URL(p.baseUrl);
  if (u.protocol !== "https:" || u.hostname !== p.host || u.port !== "") throw new ConfigError(`provider ${p.host}: https on the pinned host only`);
  if (u.username || u.password || u.search || u.hash) throw new ConfigError(`provider ${p.host}: no credentials, query or fragment in baseUrl`);
  if (p.apiKeyEnv !== undefined && !/^[A-Z][A-Z0-9_]{2,63}$/.test(p.apiKeyEnv)) throw new ConfigError(`provider ${p.host}: apiKeyEnv must be an env var NAME (A-Z0-9_)`);
  if (X_API_KEY_PROVIDER_HOSTS.includes(p.host) && !p.apiKeyEnv) throw new ConfigError(`provider ${p.host}: needs apiKeyEnv (the key goes in the X-API-Key header, never the URL)`);
  if (p.apiKeyEnv && !X_API_KEY_PROVIDER_HOSTS.includes(p.host)) throw new ConfigError(`provider ${p.host}: apiKeyEnv is only for X-API-Key hosts`);
}

export function validateConfig(c: SignerConfig): SignerConfig {
  if (GENESIS_PINS[c.network] !== c.genesisHash) throw new ConfigError("genesis pin does not match the network");
  if (!/^[0-9a-f]{32}$/.test(c.keyId)) throw new ConfigError("keyId must be 32 hex");
  if (c.margin < 10 || c.margin > 1000) throw new ConfigError("margin");
  if (new Set(c.providers.map((p) => p.operator)).size < 2) throw new ConfigError("need providers from >= 2 operators");
  for (const p of c.providers) validatePinnedProvider(p);
  if (c.maxClockSkewS > 5) throw new ConfigError("maxClockSkewS must be <= 5");
  if (c.attestTtlS < 30 || c.attestTtlS > 900) throw new ConfigError("attestTtlS in [30, 900]");
  // R59-P3-1: a co-signer block scan may take up to the 240 s deadline after the primary attests
  if (c.network === "mainnet" && c.attestTtlS < 600) throw new ConfigError("attestTtlS must be >= 600 on MainNet (co-signer scan up to 240 s)");
  if (c.scan?.deadlineS !== undefined && !(Number.isInteger(c.scan.deadlineS) && c.scan.deadlineS >= 30 && c.scan.deadlineS <= 240)) throw new ConfigError("scan.deadlineS in [30, 240]");
  if (c.scan?.concurrency !== undefined && !(Number.isInteger(c.scan.concurrency) && c.scan.concurrency >= 1 && c.scan.concurrency <= 8)) throw new ConfigError("scan.concurrency in 1..8");
  if (c.policy.maxAmountMicro > 10_000n) throw new ConfigError("maxAmountMicro above 0.01 USDC");
  // R43-P3: the day limits are bounded too (0.05 USDC / 5 releases per 24 h, matching the DB limit)
  if (c.policy.maxReleasedMicroPerDay > 50_000n) throw new ConfigError("maxReleasedMicroPerDay above 0.05 USDC");
  if (c.policy.maxReleasesPerDay > 5 || c.policy.maxReleasesPerHour > 5) throw new ConfigError("release count limits above 5");
  if (c.payerMaxFee > 2000n || c.feePayerMaxFee > 2000n) throw new ConfigError("fee caps above 2000 µALGO");
  c.policy.tamperBaseCooldownS ??= 21_600;
  if (!Number.isInteger(c.policy.tamperBaseCooldownS) || c.policy.tamperBaseCooldownS < 1) throw new ConfigError("tamperBaseCooldownS");
  if (c.network === "mainnet" && c.policy.tamperBaseCooldownS < 21_600) throw new ConfigError("tamperBaseCooldownS below the MainNet floor of 6 h");
  if (c.requesters.length < 1) throw new ConfigError("no pinned requester");
  return c;
}

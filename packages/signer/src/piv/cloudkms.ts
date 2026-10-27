/**
 * Google Cloud KMS backend (rev 15, GCP hosting), behind SignBackend. The automated signer runs in a GCP VM; the
 * attestation key is a Cloud KMS key version (EC_SIGN_ED25519, protection level SOFTWARE: Cloud KMS supports
 * Ed25519 only at SOFTWARE, not HSM; see docs/ops/attested-release-signer.md §17).
 *
 * - Auth: ONLY the VM's attached service account, via the metadata server token endpoint (Metadata-Flavor: Google).
 *   No service-account key files, no gcloud, no ADC file. The token is cached in memory until 60 s before expiry and
 *   never logged or put in an error message.
 * - The key VERSION is pinned (full resource name, .../cryptoKeyVersions/N), and so is the 32-byte public key. At
 *   open(), getPublicKey must say EC_SIGN_ED25519, the pinned protection level, and a PEM whose raw key equals the
 *   pinned key (refuse: replaced / rotated / wrong key).
 * - sign(): the message must be an attestation or co-signature of this backend's network (same rule as ykcs11).
 *   Request carries dataCrc32c; the response must echo the pinned version name, verifiedDataCrc32c=true, a matching
 *   signatureCrc32c and the pinned protection level, and the signature must verify against the pinned public key
 *   before it is returned.
 * - fetch is injected (tests use a mock metadata server + mock KMS; no GCP account is touched).
 */
import { assertKeyResource } from "./backend.js";
import { assertActiveSignerKey, KeyOrderError, type KeyOrderFiles } from "./key-order.js";
import { createPublicKey } from "node:crypto";
import { decodeAttestation, decodeCosign, verifyAttestation, GENESIS_PIN_ANY } from "./ykcs11-deps.js";
import type { SignBackend } from "./backend.js";

export class CloudKmsError extends Error {}

export interface CloudKmsOptions {
  network: "testnet" | "mainnet";
  /** projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>/cryptoKeyVersions/<n> */
  keyVersionName: string;
  /** R50-P3: the key_resource pinned in the DB (v12); open() refuses unless it names this backend's key. Required on MainNet. */
  keyResource?: string;
  pubkey: Uint8Array;
  protectionLevel: "SOFTWARE" | "HSM";
  /** if set, the metadata server's default SA email must equal this (the dedicated signer SA) */
  serviceAccountEmail?: string;
  metadataBase?: string; // default http://metadata.google.internal
  kmsBase?: string; // default https://cloudkms.googleapis.com
  timeoutMs?: number;
  /** tests only: key order file paths (never set from config) */
  keyOrderFiles?: KeyOrderFiles;
}

type Fetch = (url: string, init?: { method?: string; headers?: Record<string, string>; body?: string; signal?: AbortSignal }) => Promise<{ status: number; headers: { get(n: string): string | null }; json(): Promise<unknown>; text(): Promise<string> }>;

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0x82f63b78 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; }
  return t;
})();
/** CRC32C (Castagnoli), as Cloud KMS uses for dataCrc32c / signatureCrc32c. */
export function crc32c(b: Uint8Array): number {
  let c = 0xffffffff;
  for (const x of b) c = CRC_TABLE[(c ^ x) & 0xff]! ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

const VERSION_RE = /^projects\/[a-z][a-z0-9-]{4,28}[a-z0-9]\/locations\/[a-z0-9-]+\/keyRings\/[A-Za-z0-9_-]{1,63}\/cryptoKeys\/[A-Za-z0-9_-]{1,63}\/cryptoKeyVersions\/[1-9][0-9]*$/;

export class CloudKmsBackend implements SignBackend {
  readonly kind = "cloudkms" as const;
  private token: { v: string; until: number } | null = null;
  private opened = false;
  constructor(private readonly o: CloudKmsOptions, private readonly f: Fetch = fetch as unknown as Fetch) {
    if (!VERSION_RE.test(o.keyVersionName)) throw new CloudKmsError("keyVersionName must be a full, pinned cryptoKeyVersions/N resource name");
    if (o.pubkey.length !== 32) throw new CloudKmsError("pinned pubkey must be 32 bytes");
    // R75-P2-1 / R77-P3-2: backups refused on every network; on MainNet the key must be the inventory's active signer
    assertActiveSignerKey({ network: o.network, what: "cloudkms", resource: o.keyVersionName, pubkey: o.pubkey }, process.env, o.keyOrderFiles);
    if (o.network === "mainnet" && !o.serviceAccountEmail) throw new CloudKmsError("MainNet: serviceAccountEmail must be pinned"); // R72-P3-4
    if (o.protectionLevel !== "SOFTWARE" && o.protectionLevel !== "HSM") throw new CloudKmsError("protectionLevel");
    const kb = o.kmsBase ?? "https://cloudkms.googleapis.com";
    if (!/^https:\/\//.test(kb) && !/^http:\/\/127\.0\.0\.1:/.test(kb)) throw new CloudKmsError("kmsBase must be https");
  }

  private sig(): AbortSignal { return AbortSignal.timeout(this.o.timeoutMs ?? 10_000); }
  private md(p: string) { return `${this.o.metadataBase ?? "http://metadata.google.internal"}/computeMetadata/v1/instance/service-accounts/default/${p}`; }

  private async mdGet(p: string): Promise<{ status: number; body: unknown; text: string }> {
    let r;
    try { r = await this.f(this.md(p), { headers: { "Metadata-Flavor": "Google" }, signal: this.sig() }); } catch (e) { throw new CloudKmsError(`metadata server unreachable (${(e as Error).name})`); }
    if (r.headers.get("metadata-flavor") !== "Google") throw new CloudKmsError("metadata response lacks Metadata-Flavor: Google (not the GCE metadata server)");
    const text = await r.text();
    let body: unknown = null; try { body = JSON.parse(text); } catch { /* email is text */ }
    return { status: r.status, body, text };
  }

  private async accessToken(): Promise<string> {
    if (this.token && Date.now() < this.token.until) return this.token.v;
    if (this.o.serviceAccountEmail) {
      const e = await this.mdGet("email");
      if (e.status !== 200 || e.text.trim() !== this.o.serviceAccountEmail) throw new CloudKmsError("the VM's attached service account is not the pinned signer service account");
    }
    const t = await this.mdGet("token");
    const b = t.body as { access_token?: string; expires_in?: number; token_type?: string } | null;
    if (t.status !== 200 || !b?.access_token || b.token_type !== "Bearer" || !(Number(b.expires_in) > 0)) throw new CloudKmsError(`metadata token request failed (status ${t.status})`);
    this.token = { v: b.access_token, until: Date.now() + Math.max(0, Number(b.expires_in) - 60) * 1000 };
    return this.token.v;
  }

  private async kms(method: "GET" | "POST", suffix: string, body?: unknown): Promise<Record<string, unknown>> {
    const tok = await this.accessToken();
    let r;
    try {
      r = await this.f(`${this.o.kmsBase ?? "https://cloudkms.googleapis.com"}/v1/${this.o.keyVersionName}${suffix}`, {
        method, headers: { authorization: `Bearer ${tok}`, "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined, signal: this.sig() });
    } catch (e) { throw new CloudKmsError(`Cloud KMS unreachable (${(e as Error).name})`); }
    if (r.status === 401) this.token = null;
    if (r.status !== 200) throw new CloudKmsError(`Cloud KMS ${suffix || "get"} status ${r.status}`);
    return (await r.json()) as Record<string, unknown>;
  }

  /** Checks the pinned key version (algorithm, protection level, public key). Idempotent. */
  async open(): Promise<void> {
    if (this.opened) return;
    assertKeyResource(this.o.network, this.o.keyResource, this.o.keyVersionName);
    const pk = await this.kms("GET", "/publicKey");
    if (pk.algorithm !== "EC_SIGN_ED25519") throw new CloudKmsError(`key version algorithm is ${String(pk.algorithm)}, not EC_SIGN_ED25519`);
    if (pk.protectionLevel !== this.o.protectionLevel) throw new CloudKmsError("key version protection level is not the pinned one");
    if (pk.name !== this.o.keyVersionName) throw new CloudKmsError("publicKey response names another key version");
    let raw: Uint8Array;
    try { raw = new Uint8Array(createPublicKey(String(pk.pem)).export({ format: "der", type: "spki" }).subarray(12)); } catch { throw new CloudKmsError("unparseable public key PEM"); }
    if (!Buffer.from(raw).equals(Buffer.from(this.o.pubkey))) throw new CloudKmsError("the KMS key version's public key is not the pinned public key");
    this.opened = true;
  }

  async publicKey(): Promise<Uint8Array> { return this.o.pubkey; }

  async sign(msg: Uint8Array): Promise<Uint8Array> {
    let b: { network: string; genesisHash: string };
    try { b = decodeAttestation(msg); } catch {
      try { b = decodeCosign(msg); } catch { throw new CloudKmsError("refusing to sign: not an attestation / co-signature message"); }
    }
    if (b.network !== this.o.network || b.genesisHash !== GENESIS_PIN_ANY[this.o.network]) throw new CloudKmsError("refusing to sign: message network / genesis is not this backend's");
    await this.open();
    const r = await this.kms("POST", ":asymmetricSign", { data: Buffer.from(msg).toString("base64"), dataCrc32c: String(crc32c(msg)) });
    if (r.name !== this.o.keyVersionName) throw new CloudKmsError("asymmetricSign response names another key version");
    if (r.verifiedDataCrc32c !== true) throw new CloudKmsError("Cloud KMS did not verify the request CRC32C");
    if (r.protectionLevel !== this.o.protectionLevel) throw new CloudKmsError("signature protection level is not the pinned one");
    const sig = new Uint8Array(Buffer.from(String(r.signature ?? ""), "base64"));
    if (String(r.signatureCrc32c) !== String(crc32c(sig))) throw new CloudKmsError("signature CRC32C mismatch (corrupted in transit)");
    if (sig.length !== 64 || !verifyAttestation(msg, sig, this.o.pubkey)) throw new CloudKmsError("KMS signature does not verify against the pinned key");
    return sig;
  }
}

/** Builds the backend from MR_KMS_CONFIG JSON (deploy/gcp/cloudkms.example.json). */
export function cloudKmsFromConfig(j: { role?: string; network: "testnet" | "mainnet"; keyVersionName: string; pubkeyB64: string; protectionLevel: "SOFTWARE" | "HSM"; serviceAccountEmail?: string; metadataBase?: string; keyResource?: string }): CloudKmsBackend {
  // R75-P2-1: a config marked backup, a backup key, or (MainNet) a key that is not the inventory's active signer is refused
  if (j.role !== undefined && j.role !== "active") throw new KeyOrderError(`cloudkms config has role ${String(j.role)}: backups never sign (docs/ops/kms-key-order.md)`);
  if (j.network === "mainnet" && !j.serviceAccountEmail) throw new CloudKmsError("MainNet: serviceAccountEmail must be pinned");
  if (j.metadataBase && !/^http:\/\/(169\.254\.169\.254|metadata\.google\.internal)$/.test(j.metadataBase)) throw new CloudKmsError("metadataBase must be the GCE metadata server");
  return new CloudKmsBackend({ network: j.network, keyVersionName: j.keyVersionName, pubkey: new Uint8Array(Buffer.from(j.pubkeyB64, "base64")), protectionLevel: j.protectionLevel, serviceAccountEmail: j.serviceAccountEmail, metadataBase: j.metadataBase, keyResource: j.keyResource });
}

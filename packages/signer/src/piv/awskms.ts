/**
 * AWS KMS backend (R48-P2-1): the second verifier's key OUTSIDE Google. KMS key spec ECC_NIST_EDWARDS25519,
 * SigningAlgorithm ED25519_SHA_512 with MessageType RAW (PureEdDSA over the message bytes, as mr_ed25519 verifies;
 * AWS KMS key spec reference + Sign API). Keys live in AWS KMS HSMs.
 *
 * - Credentials: ONLY the EC2 instance role, through IMDSv2 (PUT /latest/api/token, then
 *   /latest/meta-data/iam/security-credentials/<role>). The role name is pinned; no access-key files, no env keys.
 *   Credentials are cached in memory until 5 min before Expiration and never logged or put into errors.
 * - Requests are SigV4-signed (service "kms") JSON 1.1 calls: TrentService.GetPublicKey / TrentService.Sign.
 * - Pinned: region, full key ARN, 32-byte public key. open() requires KeySpec ECC_NIST_EDWARDS25519, KeyUsage
 *   SIGN_VERIFY, ED25519_SHA_512 offered, the response KeyId == pinned ARN and the SPKI == pinned key.
 * - sign(): attestation / co-signature of this backend's network only; the response must name the pinned ARN and
 *   ED25519_SHA_512, and the signature must verify against the pinned key before it is returned.
 */
import { assertKeyResource } from "./backend.js";
import { assertNotBackupKey } from "./key-order.js";
import { createPublicKey } from "node:crypto";
import { decodeAttestation, decodeCosign, verifyAttestation, GENESIS_PIN_ANY } from "./ykcs11-deps.js";
import { sigV4 } from "../sinks/s3.js";
import type { SignBackend } from "./backend.js";

export class AwsKmsError extends Error {}

export interface AwsKmsOptions {
  network: "testnet" | "mainnet";
  region: string;
  /** arn:aws:kms:<region>:<account>:key/<uuid> (not an alias) */
  keyArn: string;
  /** R50-P3: the key_resource pinned in the DB (v12); open() refuses unless it names this backend's key. Required on MainNet. */
  keyResource?: string;
  pubkey: Uint8Array;
  /** the instance profile role name, pinned */
  roleName: string;
  imdsBase?: string; // default http://169.254.169.254 (EC2 IMDSv2); R77-P3-4: the Roles Anywhere source was removed
  kmsEndpoint?: string; // default https://kms.<region>.amazonaws.com
  timeoutMs?: number;
}

type Fetch = (url: string, init?: { method?: string; headers?: Record<string, string>; body?: string; signal?: AbortSignal }) => Promise<{ status: number; json(): Promise<unknown>; text(): Promise<string> }>;
interface Creds { AccessKeyId: string; SecretAccessKey: string; Token: string; until: number }

const ARN_RE = /^arn:aws:kms:([a-z0-9-]+):[0-9]{12}:key\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export class AwsKmsBackend implements SignBackend {
  readonly kind = "awskms" as const;
  private creds: Creds | null = null;
  private opened = false;
  constructor(private readonly o: AwsKmsOptions, private readonly f: Fetch = fetch as unknown as Fetch, private readonly now: () => Date = () => new Date()) {
    const m = ARN_RE.exec(o.keyArn);
    if (!m) throw new AwsKmsError("keyArn must be a full KMS key ARN (no alias)");
    if (m[1] !== o.region) throw new AwsKmsError("keyArn region differs from region");
    // R77-P3-4: never on MainNet (the only MainNet co-signer is aliyun-softkey; the AWS key is a locked backup)
    if ((o.network as string) !== "testnet") throw new AwsKmsError(`awskms is refused on ${String(o.network)}: AWS KMS is not a MainNet signer or co-signer (docs/ops/kms-key-order.md)`);
    assertNotBackupKey({ network: o.network, what: "awskms", resource: o.keyArn, pubkey: o.pubkey }); // R75-P2-1: the AWS key is a locked backup
    if (o.pubkey.length !== 32) throw new AwsKmsError("pinned pubkey must be 32 bytes");
    if (!/^[\w+=,.@-]{1,64}$/.test(o.roleName)) throw new AwsKmsError("roleName");
    const ep = this.endpoint();
    if (!/^https:\/\//.test(ep) && !/^http:\/\/127\.0\.0\.1:/.test(ep)) throw new AwsKmsError("kmsEndpoint must be https");
  }
  private endpoint() { return this.o.kmsEndpoint ?? `https://kms.${this.o.region}.amazonaws.com`; }
  private sig(): AbortSignal { return AbortSignal.timeout(this.o.timeoutMs ?? 10_000); }

  private async call(url: string, init: Parameters<Fetch>[1], what: string) {
    try { return await this.f(url, { ...init, signal: this.sig() }); } catch (e) { throw new AwsKmsError(`${what} unreachable (${(e as Error).name})`); }
  }

  private async credentials(): Promise<Creds> {
    if (this.creds && this.now().getTime() < this.creds.until) return this.creds;
    const base = this.o.imdsBase ?? "http://169.254.169.254";
    const t = await this.call(`${base}/latest/api/token`, { method: "PUT", headers: { "X-aws-ec2-metadata-token-ttl-seconds": "300" } }, "IMDSv2");
    if (t.status !== 200) throw new AwsKmsError(`IMDSv2 token status ${t.status}`);
    const tok = (await t.text()).trim();
    const h = { "X-aws-ec2-metadata-token": tok };
    const r = await this.call(`${base}/latest/meta-data/iam/security-credentials/`, { headers: h }, "IMDSv2");
    const roles = r.status === 200 ? (await r.text()).split("\n").map((x) => x.trim()).filter(Boolean) : [];
    if (roles.length !== 1 || roles[0] !== this.o.roleName) throw new AwsKmsError("the instance role is not the pinned verifier role");
    const c = await this.call(`${base}/latest/meta-data/iam/security-credentials/${this.o.roleName}`, { headers: h }, "IMDSv2");
    const j = (c.status === 200 ? await c.json() : null) as { Code?: string; AccessKeyId?: string; SecretAccessKey?: string; Token?: string; Expiration?: string } | null;
    if (!j || j.Code !== "Success" || !j.AccessKeyId || !j.SecretAccessKey || !j.Token || !Number.isFinite(Date.parse(j.Expiration ?? ""))) throw new AwsKmsError(`IMDSv2 role credentials unavailable (status ${c.status})`);
    this.creds = { AccessKeyId: j.AccessKeyId, SecretAccessKey: j.SecretAccessKey, Token: j.Token, until: Date.parse(j.Expiration!) - 5 * 60_000 };
    return this.creds;
  }

  private async kms(target: "GetPublicKey" | "Sign", body: Record<string, unknown>): Promise<Record<string, unknown>> {
    const c = await this.credentials();
    const url = new URL(`${this.endpoint()}/`);
    const payload = JSON.stringify(body);
    const headers = sigV4({ region: this.o.region, accessKeyId: c.AccessKeyId, secretAccessKey: c.SecretAccessKey }, "POST", url,
      { "content-type": "application/x-amz-json-1.1", "x-amz-target": `TrentService.${target}`, "x-amz-security-token": c.Token }, payload, this.now(), "kms");
    const r = await this.call(url.toString(), { method: "POST", headers, body: payload }, "AWS KMS");
    if (r.status === 400 || r.status === 403) { const t = await r.text(); const ty = /"__type"\s*:\s*"([^"]+)"/.exec(t)?.[1] ?? "error"; if (/Expired|InvalidSignature|UnrecognizedClient/.test(ty)) this.creds = null; throw new AwsKmsError(`AWS KMS ${target} ${r.status} ${ty.replace(/^.*#/, "")}`); }
    if (r.status !== 200) throw new AwsKmsError(`AWS KMS ${target} status ${r.status}`);
    return (await r.json()) as Record<string, unknown>;
  }

  async open(): Promise<void> {
    if (this.opened) return;
    assertKeyResource(this.o.network, this.o.keyResource, this.o.keyArn);
    const pk = await this.kms("GetPublicKey", { KeyId: this.o.keyArn });
    if (pk.KeyId !== this.o.keyArn) throw new AwsKmsError("GetPublicKey answered for another key");
    if (pk.KeySpec !== "ECC_NIST_EDWARDS25519") throw new AwsKmsError(`key spec is ${String(pk.KeySpec)}, not ECC_NIST_EDWARDS25519`);
    if (pk.KeyUsage !== "SIGN_VERIFY") throw new AwsKmsError("key usage is not SIGN_VERIFY");
    if (!Array.isArray(pk.SigningAlgorithms) || !pk.SigningAlgorithms.includes("ED25519_SHA_512")) throw new AwsKmsError("key does not offer ED25519_SHA_512");
    let raw: Uint8Array;
    try { raw = new Uint8Array(createPublicKey({ key: Buffer.from(String(pk.PublicKey), "base64"), format: "der", type: "spki" }).export({ format: "der", type: "spki" }).subarray(12)); } catch { throw new AwsKmsError("unparseable public key"); }
    if (!Buffer.from(raw).equals(Buffer.from(this.o.pubkey))) throw new AwsKmsError("the KMS key's public key is not the pinned public key");
    this.opened = true;
  }

  async publicKey(): Promise<Uint8Array> { return this.o.pubkey; }

  async sign(msg: Uint8Array): Promise<Uint8Array> {
    let b: { network: string; genesisHash: string };
    try { b = decodeAttestation(msg); } catch {
      try { b = decodeCosign(msg); } catch { throw new AwsKmsError("refusing to sign: not an attestation / co-signature message"); }
    }
    if (b.network !== this.o.network || b.genesisHash !== GENESIS_PIN_ANY[this.o.network]) throw new AwsKmsError("refusing to sign: message network / genesis is not this backend's");
    if (msg.length > 4096) throw new AwsKmsError("message over the 4096-byte KMS RAW limit");
    await this.open();
    const r = await this.kms("Sign", { KeyId: this.o.keyArn, Message: Buffer.from(msg).toString("base64"), MessageType: "RAW", SigningAlgorithm: "ED25519_SHA_512" });
    if (r.KeyId !== this.o.keyArn) throw new AwsKmsError("Sign answered for another key");
    if (r.SigningAlgorithm !== "ED25519_SHA_512") throw new AwsKmsError("Sign used another algorithm");
    const sig = new Uint8Array(Buffer.from(String(r.Signature ?? ""), "base64"));
    if (sig.length !== 64 || !verifyAttestation(msg, sig, this.o.pubkey)) throw new AwsKmsError("KMS signature does not verify against the pinned key");
    return sig;
  }
}

export function awsKmsFromConfig(j: { network: "testnet" | "mainnet"; region: string; keyArn: string; pubkeyB64: string; roleName: string; keyResource?: string }): AwsKmsBackend {
  return new AwsKmsBackend({ network: j.network, region: j.region, keyArn: j.keyArn, pubkey: new Uint8Array(Buffer.from(j.pubkeyB64, "base64")), roleName: j.roleName, keyResource: j.keyResource });
}

import { createHash, randomBytes, sign as edSign } from "node:crypto";
import { mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import type { AuditSink } from "../src/audit.js";
import { DurableJson } from "../src/state.js";
import { initialReqState, RequestAuth, signRequest, type ReqState } from "../src/requests.js";
import { initialReconcileState, Reconciler, type ReconcileState } from "../src/verifier/reconcile.js";
import { mintGcpToken, writeTokenFile } from "../src/verifier/gcp-token.js";
import { assertKeyResource } from "../src/piv/backend.js";
import { AwsKmsBackend } from "../src/piv/awskms.js";
import { CloudKmsBackend } from "../src/piv/cloudkms.js";
import { signerServer } from "../src/server.js";
import type { MrSigner } from "../src/signer.js";
import { edKey } from "./fixtures.js";

const H = (l: string) => createHash("sha256").update(l).digest("hex");
const tmp = () => mkdtempSync(path.join(tmpdir(), "r50-"));
const T0 = Date.parse("2026-10-20T00:00:00Z");
const KV = "projects/mr-signer-prod/locations/us-east1/keyRings/mr/cryptoKeys/attest/cryptoKeyVersions/1";
const ARN = "arn:aws:kms:us-east-1:111111111111:key/00000000-0000-0000-0000-000000000000";

describe("R50-P3 key_resource pin checked at open()", () => {
  it("assertKeyResource: required on MainNet, must equal the configured key", () => {
    expect(() => assertKeyResource("mainnet", undefined, KV)).toThrow(/required on MainNet/);
    expect(() => assertKeyResource("testnet", undefined, KV)).not.toThrow();
    expect(() => assertKeyResource("mainnet", KV.replace(/1$/, "2"), KV)).toThrow(/does not name the configured key/);
    expect(() => assertKeyResource("mainnet", KV, KV)).not.toThrow();
  });
  it("Cloud KMS and AWS KMS backends refuse a mismatched pin before any network call", async () => {
    let calls = 0;
    const { mkdtempSync, writeFileSync } = await import("node:fs"); const { tmpdir } = await import("node:os"); const { join } = await import("node:path");
    const inventoryPath = join(mkdtempSync(join(tmpdir(), "inv-")), "kms-keys.json");
    writeFileSync(inventoryPath, JSON.stringify({ order: ["aliyun-softkey"], active: { cosigner: "aliyun-softkey", signer: "s" }, s: { role: "active", keyVersionName: KV } }));
    const keyOrderFiles = { inventoryPath };
    const f = (async () => { calls++; throw new Error("no network"); }) as never;
    const ck = new CloudKmsBackend({ network: "mainnet", keyVersionName: KV, keyResource: KV.replace(/1$/, "9"), pubkey: new Uint8Array(32), protectionLevel: "SOFTWARE", serviceAccountEmail: "sa@p.iam.gserviceaccount.com", keyOrderFiles }, f);
    // R72-P3-4: direct construction on MainNet without a pinned SA is refused
    expect(() => new CloudKmsBackend({ network: "mainnet", keyVersionName: KV, keyResource: KV, pubkey: new Uint8Array(32), protectionLevel: "SOFTWARE", keyOrderFiles }, f)).toThrow(/serviceAccountEmail must be pinned/);
    await expect(ck.open()).rejects.toThrow(/does not name the configured key/);
    const ak = new AwsKmsBackend({ network: "testnet", region: "us-east-1", keyArn: ARN, keyResource: ARN.replace("1111", "2222"), pubkey: new Uint8Array(32), roleName: "mr-verifier" }, f);
    await expect(ak.open()).rejects.toThrow(/does not name the configured key/);
    expect(calls).toBe(0);
  });
});

describe("R50-P3 reconciler mismatch acknowledge path", () => {
  it("signed ack must name the exact problem hash and a reason; cursor then moves past that window only; paged", async () => {
    const f = path.join(tmp(), "r.json"); DurableJson.init<ReconcileState>(f, initialReconcileState(T0));
    const st = new DurableJson<ReconcileState>(f);
    const lines: string[] = [];
    const chain: AuditSink = { append: async () => {}, last: async () => lines.at(-1) ?? null, at: async (s) => lines[s - 1] ?? null };
    const pins = { keyVersion: KV, signerSa: "sa@p.iam.gserviceaccount.com", signerIp: "10.10.0.5", signerNetwork: "n" };
    const pages: string[] = [];
    let now = T0 + 3_600_000;
    const r = new Reconciler(pins, { kms: { list: async () => [{ insertId: "x", at: T0 + 1000, principal: pins.signerSa, callerIp: "10.10.0.5", callerNetwork: "n", keyVersion: KV }] }, chain, st, page: async (s) => { pages.push(s); }, now: () => now });
    expect((await r.tick()).length).toBe(1);
    const open = r.status().open!;
    expect(open.hash).toMatch(/^[0-9a-f]{64}$/);
    const k = edKey();
    const rf = path.join(tmp(), "q.json"); DurableJson.init<ReqState>(rf, initialReqState());
    const auth = new RequestAuth([{ id: "david", pubkey: k.pub }], new DurableJson<ReqState>(rf), { maxAgeS: 120, ratePerHour: 6, network: "testnet" }, () => now);
    const body = (o: Record<string, string>) => ({ op: "reconcile-ack", requester: "david", network: "testnet", ts: new Date(now).toISOString(), reqNonce: randomBytes(32).toString("base64url"), ...o });
    await expect(r.acknowledge(signRequest(body({ hash: "0".repeat(64), reason: "checked the console, test sign" }), k.priv), auth)).rejects.toThrow(/another problem set/);
    await expect(r.acknowledge(signRequest(body({ hash: open.hash, reason: "short" }), k.priv), auth)).rejects.toThrow(/reason/);
    const other = edKey();
    await expect(r.acknowledge(signRequest(body({ hash: open.hash, reason: "checked the console, test sign" }), other.priv), auth)).rejects.toThrow(/signature/);
    const ok = await r.acknowledge(signRequest(body({ hash: open.hash, reason: "checked the console, test sign" }), k.priv), auth);
    expect(ok.cursorMs).toBe(open.windowTo);
    expect(pages.at(-1)).toMatch(/ACKNOWLEDGED/);
    expect(st.get().acks?.[0]).toMatchObject({ by: "david", hash: open.hash });
    expect(r.status().open).toBeNull();
    await expect(r.acknowledge(signRequest(body({ hash: open.hash, reason: "checked the console, test sign" }), k.priv), auth)).rejects.toThrow(/nothing to acknowledge/);
    void H; void lines;
  });
});

describe("R51-P3 reconcile ack hash + full problem list", () => {
  it("hash is stable while the window end moves; status lists every problem (> 50)", async () => {
    const f = path.join(tmp(), "r.json"); DurableJson.init<ReconcileState>(f, initialReconcileState(T0));
    const st = new DurableJson<ReconcileState>(f);
    const chain: AuditSink = { append: async () => {}, last: async () => null, at: async () => null };
    const pins = { keyVersion: KV, signerSa: "sa@p.iam.gserviceaccount.com", signerIp: "10.10.0.5", signerNetwork: "n" };
    const entries = Array.from({ length: 70 }, (_, i) => ({ insertId: `x${i}`, at: T0 + 1000 + i * 1000, principal: pins.signerSa, callerIp: "10.10.0.5", callerNetwork: "n", keyVersion: KV }));
    let now = T0 + 3_600_000;
    const r = new Reconciler(pins, { kms: { list: async () => entries }, chain, st, page: async () => {}, now: () => now });
    expect((await r.tick()).length).toBe(70);
    const a = r.status();
    expect(a.problemCount).toBe(70);
    expect(a.open!.problems.length).toBe(70);
    now += 300_000;
    await r.tick();
    const b = r.status();
    expect(b.open!.windowTo).toBeGreaterThan(a.open!.windowTo);
    expect(b.open!.hash).toBe(a.open!.hash);
  });
});

describe("R50-P2 GCP token via Workload Identity Federation (mock IMDS + Google STS + IAM Credentials)", () => {
  it("signs GetCallerIdentity as the subject token, exchanges, impersonates the reader SA with logging.read; writes 0600", async () => {
    const seen: Record<string, any> = {};
    const f = (async (u: string, i: any = {}) => {
      const R = (status: number, b: unknown) => ({ status, json: async () => b, text: async () => (typeof b === "string" ? b : JSON.stringify(b)) });
      if (u.endsWith("/latest/api/token")) return R(200, "imds-tok");
      if (u.includes("/security-credentials/mr-verifier")) return R(200, { Code: "Success", AccessKeyId: "AKIA", SecretAccessKey: "s", Token: "t" });
      if (u.endsWith("/v1/token")) { seen.sts = Object.fromEntries(new URLSearchParams(i.body)); return R(200, { access_token: "fed" }); }
      if (u.includes(":generateAccessToken")) { seen.iam = { u, auth: i.headers.authorization, body: JSON.parse(i.body) }; return R(200, { accessToken: "ya29.reader", expireTime: "2026-10-20T01:00:00Z" }); }
      return R(404, "");
    }) as never;
    const prov = "projects/123456/locations/global/workloadIdentityPools/mr-verifier-aws/providers/aws-verifier";
    const out = await mintGcpToken({ awsRegion: "us-east-1", roleName: "mr-verifier", wifProvider: prov, readerSa: "mr-reconcile-reader@p-1.iam.gserviceaccount.com", imdsBase: "http://imds" }, f, () => new Date(T0));
    expect(out.token).toBe("ya29.reader");
    expect(seen.sts.subject_token_type).toBe("urn:ietf:params:aws:token-type:aws4_request");
    expect(seen.sts.audience).toBe(`//iam.googleapis.com/${prov}`);
    const subj = JSON.parse(decodeURIComponent(seen.sts.subject_token));
    expect(subj.url).toContain("Action=GetCallerIdentity");
    const hs = Object.fromEntries(subj.headers.map((x: any) => [x.key, x.value]));
    expect(hs["x-goog-cloud-target-resource"]).toBe(`//iam.googleapis.com/${prov}`);
    expect(hs.authorization).toMatch(/^AWS4-HMAC-SHA256 Credential=AKIA\/20261020\/us-east-1\/sts\/aws4_request, SignedHeaders=.*x-goog-cloud-target-resource/);
    expect(seen.iam.auth).toBe("Bearer fed");
    expect(seen.iam.body.scope).toEqual(["https://www.googleapis.com/auth/logging.read"]);
    const file = path.join(tmp(), "gcp-token");
    writeTokenFile(file, out.token);
    expect(readFileSync(file, "utf8")).toBe("ya29.reader");
    expect(statSync(file).mode & 0o777).toBe(0o600);
    await expect(mintGcpToken({ awsRegion: "us-east-1", roleName: "r", wifProvider: "bad", readerSa: "x@y.iam.gserviceaccount.com" }, f)).rejects.toThrow(/provider resource/);
  });
  it("timer + WIF config are in the repo", () => {
    const D = new URL("../../../deploy/", import.meta.url);
    const wif = readFileSync(new URL("gcp/alerts/wif.tf", D), "utf8");
    expect(wif).toContain("google_iam_workload_identity_pool_provider");
    expect(wif).toContain("roles/logging.privateLogViewer");
    expect(wif).toMatch(/attribute_condition = .*assumed-role\/\$\{var.verifier_aws_role\}\/i-/);
    expect(readFileSync(new URL("verifier/mr-gcp-token.timer", D), "utf8")).toContain("OnUnitActiveSec=20min");
    expect(readFileSync(new URL("verifier/mr-gcp-token.service", D), "utf8")).toContain("User=mr-verifier");
  });
});

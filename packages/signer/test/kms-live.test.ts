/**
 * Backup KMS keys (GCP + AWS) — pin-file consistency, plus an opt-in live check (MR_KMS_LIVE=1) that both backups
 * REFUSE to sign (they are locked; the active co-signer is aliyun-softkey). The live part uses ambient gcloud ADC
 * and AWS env credentials; it never prints them. Key order: docs/ops/kms-key-order.md.
 */
import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdtempSync, rmSync, existsSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { tmpdir } from "node:os";
import path from "node:path";
import { cloudKmsFromConfig } from "../src/piv/cloudkms.js";

const D = path.join(__dirname, "../../../deploy");
const K = JSON.parse(readFileSync(path.join(D, "mainnet/kms-keys.json"), "utf8"));
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function algoAddr(pk: Buffer): string {
  const b = Buffer.concat([pk, createHash("sha512-256").update(pk).digest().subarray(28)]);
  let bits = ""; for (const x of b) bits += x.toString(2).padStart(8, "0");
  let o = ""; for (let i = 0; i < bits.length; i += 5) o += B32[parseInt(bits.slice(i, i + 5).padEnd(5, "0"), 2)];
  return o;
}

describe("backup KMS key pin files", () => {
  it("key order is aliyun-softkey, gcp, aws and GCP is the active signer, AWS backup-only", () => {
    expect(K.order).toEqual(["aliyun-softkey", "gcp", "aws"]);
    expect(K.gcp.role).toBe("active"); expect(K.aws.role).toBe("backup");
    expect(K.gcp.backend).toBe("cloudkms"); expect(K.aws.backend).toBe("awskms");
    expect(K.cosigner).toBeUndefined();
  });
  it("addresses derive from pinned pubkeys, are distinct, and resources match their project/account", () => {
    for (const k of [K.gcp, K.aws]) expect(algoAddr(Buffer.from(k.pubkeyB64, "base64"))).toBe(k.algorandAddress);
    expect(K.gcp.algorandAddress).not.toBe(K.aws.algorandAddress);
    expect(K.gcp.keyVersionName.split("/")[1]).toBe(K.gcp.project);
    expect(K.aws.keyArn.split(":")[4]).toBe(K.aws.accountId);
    expect(K.aws.keyArn.split(":")[3]).toBe(K.aws.region);
  });
  it("2026-10-22 19:31 ET: the GCP config is the active MainNet signer config; desired key IAM is mr-signer only", () => {
    expect(existsSync(path.join(D, "gcp/cloudkms.gcp-backup.json"))).toBe(false);
    const ck = JSON.parse(readFileSync(path.join(D, "gcp/cloudkms.mainnet.json"), "utf8"));
    expect(ck.role).toBe("active"); expect(ck.network).toBe("mainnet");
    expect(ck.keyVersionName).toBe(K.gcp.keyVersionName);
    expect(ck.keyResource).toBe(K.gcp.keyVersionName);
    expect(ck.pubkeyB64).toBe(K.gcp.pubkeyB64);
    expect(ck.serviceAccountEmail).toBe(K.gcp.serviceAccountEmail);
    expect(K.active).toEqual({ cosigner: "aliyun-softkey", signer: "gcp" });
    expect(cloudKmsFromConfig(ck).kind).toBe("cloudkms"); // local checks only; live usability needs the IAM/version changes in kms-key-order.md
    expect(readFileSync(path.join(D, "gcp/mr-piv-sign@.service"), "utf8")).toMatch(/MR_KMS_CONFIG=\/etc\/mr-piv\/cloudkms\.mainnet\.json/);
    const iam = JSON.parse(readFileSync(path.join(D, "gcp/kms-signer-iam.json"), "utf8"));
    expect(iam.bindings).toEqual([{ role: "roles/cloudkms.signerVerifier", members: [`serviceAccount:${K.gcp.serviceAccountEmail}`] }]);
  });
  it("no AWS co-signer wiring; AWS backup policy keeps root admin and denies Sign for all", () => {
    expect(existsSync(path.join(D, "verifier/awskms.mainnet.json"))).toBe(false);
    expect(existsSync(path.join(D, "aws/imports.tf"))).toBe(false);
    const p = JSON.parse(readFileSync(path.join(D, "aws/backup/key-policy.backup-locked.json"), "utf8"));
    const s = p.Statement as Array<Record<string, any>>;
    expect(s.some((x) => x.Effect === "Allow" && x.Principal?.AWS === `arn:aws:iam::${K.aws.accountId}:root` && x.Action === "kms:*")).toBe(true);
    // R75-P3-3: the deny must be unconditional and cover the whole key (Resource "*" = this key in a key policy)
    for (const a of ["kms:Sign", "kms:ScheduleKeyDeletion"]) {
      const d = s.filter((x) => x.Effect === "Deny" && x.Action === a);
      expect(d.length).toBe(1);
      expect(d[0].Principal).toEqual({ AWS: "*" });
      expect(d[0].Resource).toBe("*");
      expect(d[0].Condition).toBeUndefined();
      expect(d[0].NotAction ?? d[0].NotPrincipal ?? d[0].NotResource).toBeUndefined();
    }
    expect(s.filter((x) => x.Effect === "Allow").length).toBe(1);
  });
  it("R75-P2-2: drift check passes on an identical (reordered) policy and fails on a removed deny", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "drift-"));
    try {
      const pol = JSON.parse(readFileSync(path.join(D, "aws/backup/key-policy.backup-locked.json"), "utf8"));
      const run = (p: unknown) => {
        writeFileSync(path.join(dir, "p.json"), JSON.stringify(p));
        writeFileSync(path.join(dir, "aws"), `#!/bin/sh\ncat "${path.join(dir, "p.json")}"\n`, { mode: 0o755 });
        try { return { code: 0, out: execFileSync(path.join(D, "aws/backup/check-key-policy.sh"), { env: { ...process.env, PATH: `${dir}:${process.env.PATH}` }, stdio: "pipe" }).toString() }; }
        catch (e) { return { code: (e as { status: number }).status, out: String((e as { stdout?: Buffer }).stdout ?? "") }; }
      };
      expect(run({ ...pol, Statement: [...pol.Statement].reverse() }).code).toBe(0);
      const r = run({ ...pol, Statement: pol.Statement.filter((x: any) => x.Action !== "kms:Sign") });
      expect(r.code).toBe(1); expect(r.out).toMatch(/DRIFT/);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
  it("R75-P3-2 / R76-P3-6: no Terraform in deploy/ creates an AWS KMS key or wires AWS as a co-signer", () => {
    const tfs = execFileSync("find", [D, "-name", "*.tf"], { encoding: "utf8" }).split("\n").filter(Boolean);
    expect(tfs.length).toBeGreaterThan(0);
    for (const f of tfs) expect(readFileSync(f, "utf8"), f).not.toMatch(/resource\s+"aws_kms_key|aws_rolesanywhere_|aws_instance"/);
  });
});

describe.skipIf(process.env.MR_KMS_LIVE !== "1")("live: KMS keys (GCP signer enabled; AWS backup locked)", () => {
  const msg = randomBytes(64);
  const opts = { stdio: "pipe" as const, timeout: 45_000 };
  it("GCP signer key (read-only): version 1 ENABLED, Ed25519 SOFTWARE, key IAM = exactly kms-signer-iam.json", () => {
    const v = K.gcp.keyVersionName.split("/");
    const loc = ["--project", v[1]!, "--location", v[3]!, "--keyring", v[5]!];
    const d = JSON.parse(execFileSync("gcloud", ["kms", "keys", "versions", "describe", v[9]!, "--key", v[7]!, ...loc, "--format", "json"], opts).toString());
    expect(d.state).toBe("ENABLED"); expect(d.algorithm).toBe("EC_SIGN_ED25519"); expect(d.protectionLevel).toBe("SOFTWARE");
    const pol = JSON.parse(execFileSync("gcloud", ["kms", "keys", "get-iam-policy", v[7]!, ...loc, "--format", "json"], opts).toString());
    const want = JSON.parse(readFileSync(path.join(D, "gcp/kms-signer-iam.json"), "utf8")).bindings;
    expect((pol.bindings ?? []).map((b: { role: string; members: string[] }) => ({ role: b.role, members: b.members }))).toEqual(want);
  }, 60_000);
  it("AWS backup key refuses (explicit deny in the key policy)", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "kms-"));
    try {
      writeFileSync(path.join(dir, "m"), msg);
      let err = "";
      try {
        execFileSync("aws", ["kms", "sign", "--region", K.aws.region, "--key-id", K.aws.keyArn, "--message", `fileb://${path.join(dir, "m")}`,
          "--message-type", "RAW", "--signing-algorithm", "ED25519_SHA_512", "--query", "KeyId", "--output", "text"], opts);
      } catch (e) { err = String((e as { stderr?: Buffer }).stderr ?? ""); }
      expect(err).toMatch(/AccessDenied.*explicit deny/s);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }, 60_000);
  it("AWS live key policy matches the repo copy (drift check)", () => {
    expect(execFileSync(path.join(D, "aws/backup/check-key-policy.sh"), opts).toString()).toMatch(/^OK/);
  }, 60_000);
});

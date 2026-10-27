/** R75-P2-1: the key order is enforced: backups are refused by every loader, the MainNet co-signer is aliyun-softkey only, and no active signer = refuse. */
import { describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { ACTIVE_COSIGNER, assertActiveSignerKey, assertNotBackupKey, backupResourcesFromDoc, BUILTIN_BACKUP_KEYS, DEFAULT_INVENTORY, DEFAULT_ORDER_DOC, loadKeyOrder, parseKeyInventory } from "../src/piv/key-order.js";
import { AwsKmsBackend } from "../src/piv/awskms.js";
import { CloudKmsBackend } from "../src/piv/cloudkms.js";
import { assertPlatformConfig } from "../src/verifier/main.js";

const K = JSON.parse(readFileSync(DEFAULT_INVENTORY, "utf8"));
const GCP = K.gcp.keyVersionName as string; // the MainNet signer (active) since 2026-10-22 19:31 ET
const AWS = BUILTIN_BACKUP_KEYS.find((b) => b.name === "aws")!.resources[0]!;
const GCP_PUB = new Uint8Array(Buffer.from(K.gcp.pubkeyB64, "base64"));
const tmp = (j: unknown) => { const p = path.join(mkdtempSync(path.join(tmpdir(), "ko-")), "inv.json"); writeFileSync(p, typeof j === "string" ? j : JSON.stringify(j)); return p; };

describe("R75-P2-1 key order", () => {
  it("the built-in backup mirror equals the inventory's backups and the doc's backup lines", () => {
    const inv = parseKeyInventory(readFileSync(DEFAULT_INVENTORY, "utf8"));
    expect(inv.order[0]).toBe(ACTIVE_COSIGNER);
    expect(inv.active).toEqual({ cosigner: "aliyun-softkey", signer: "gcp" });
    expect(BUILTIN_BACKUP_KEYS.map((b) => b.name)).toEqual(["aws"]);
    const backups = Object.entries(inv.entries).filter(([, e]) => e.role === "backup");
    expect(backups.map(([n]) => n).sort()).toEqual(BUILTIN_BACKUP_KEYS.map((b) => b.name).sort());
    for (const [n, e] of backups) {
      const b = BUILTIN_BACKUP_KEYS.find((x) => x.name === n)!;
      expect(e.pubkeyB64).toBe(b.pubkeyB64);
      expect([...e.resources].sort()).toEqual([...b.resources].sort());
    }
    const doc = backupResourcesFromDoc(readFileSync(DEFAULT_ORDER_DOC, "utf8"));
    expect(doc.sort()).toEqual(["alias/mandaterail-verifier"]);
    expect(K.gcp.role).toBe("active"); expect(K.aws.role).toBe("backup");
  });
  it("loaders refuse backup keys on every network (resource, any version, or pinned pubkey)", () => {
    for (const network of ["testnet", "mainnet"]) {
      expect(() => assertNotBackupKey({ network, what: "x", resource: GCP, pubkey: GCP_PUB })).not.toThrow();
      expect(() => assertNotBackupKey({ network, what: "x", resource: `${AWS}/x` })).toThrow(/backup key/);
      expect(() => assertNotBackupKey({ network, what: "x", resource: AWS })).toThrow(/backup key/);
      expect(() => assertNotBackupKey({ network, what: "x", pubkey: Buffer.from(K.aws.pubkeyB64, "base64") })).toThrow(/belongs to a backup key/);
      expect(() => assertNotBackupKey({ network, what: "x", resource: "projects/other/locations/x/keyRings/y/cryptoKeys/z/cryptoKeyVersions/1", pubkey: new Uint8Array(32) })).not.toThrow();
    }
    expect(() => new AwsKmsBackend({ network: "testnet", region: "us-east-1", keyArn: AWS, pubkey: new Uint8Array(32), roleName: "r" })).toThrow(/awskms: .* backup key/);
    expect(() => new CloudKmsBackend({ network: "testnet", keyVersionName: "projects/mr-signer-prod/locations/us-central1/keyRings/mr/cryptoKeys/attest/cryptoKeyVersions/1", pubkey: Buffer.from(K.aws.pubkeyB64, "base64"), protectionLevel: "SOFTWARE" })).toThrow(/belongs to a backup key/);
    // the shipped GCP signer config builds on MainNet (constructor only; no network call)
    expect(new CloudKmsBackend({ network: "mainnet", keyVersionName: GCP, keyResource: GCP, pubkey: GCP_PUB, protectionLevel: "SOFTWARE", serviceAccountEmail: K.gcp.serviceAccountEmail }).kind).toBe("cloudkms");
  });
  it("fails closed: MainNet without an inventory, or with a malformed one; the built-in mirror still applies without it", () => {
    const env = { MR_KEY_INVENTORY: "/nonexistent/kms-keys.json", MR_KEY_ORDER_DOC: "/nonexistent/doc.md" };
    expect(() => loadKeyOrder("mainnet", { VITEST: "1" }, { inventoryPath: env.MR_KEY_INVENTORY, docPath: env.MR_KEY_ORDER_DOC })).toThrow(/missing \(fail closed\)/);
    expect(() => assertNotBackupKey({ network: "testnet", what: "x", resource: AWS }, env)).toThrow(/backup key/);
    expect(() => loadKeyOrder("testnet", { ...env, MR_KEY_INVENTORY: tmp("{") })).toThrow(/not JSON/);
    expect(() => loadKeyOrder("testnet", { ...env, MR_KEY_INVENTORY: tmp({ ...K, order: ["gcp", "aliyun-softkey"] }) })).toThrow(/order must start with aliyun-softkey/);
    expect(() => loadKeyOrder("testnet", { ...env, MR_KEY_INVENTORY: tmp({ ...K, active: { cosigner: "aws", signer: null } }) })).toThrow(/active.cosigner/);
    expect(() => loadKeyOrder("testnet", { ...env, MR_KEY_INVENTORY: tmp({ ...K, active: { cosigner: "aliyun-softkey", signer: "aws" } }) })).toThrow(/active.signer aws is not an entry with role active/);
    // an active signer that is also marked backup (here: by pubkey of the AWS backup) fails closed
    expect(() => loadKeyOrder("testnet", { ...env, MR_KEY_INVENTORY: tmp({ ...K, gcp: { ...K.gcp, pubkeyB64: K.aws.pubkeyB64 } }) })).toThrow(/also marked backup/);
    expect(() => loadKeyOrder("testnet", { ...env, MR_KEY_INVENTORY: tmp({ ...K, gcp: { ...K.gcp, role: "standby" } }) })).toThrow(/no role active\|backup/);
    // an extra backup entry from the inventory is refused even if the built-in mirror doesn't know it
    const extra = { ...K, x: { role: "backup", keyArn: "arn:aws:kms:eu-west-1:000000000000:key/x", pubkeyB64: Buffer.alloc(32, 5).toString("base64") } };
    expect(() => assertNotBackupKey({ network: "testnet", what: "x", resource: "arn:aws:kms:eu-west-1:000000000000:key/x" }, { ...env, MR_KEY_INVENTORY: tmp(extra) })).toThrow(/backup key/);
  });
  it("MainNet signer: the shipped active signer is the GCP key; anything else (or none defined) is refused", () => {
    const k = { network: "mainnet", resource: "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/3", pubkey: new Uint8Array(32).fill(4) };
    expect(() => assertActiveSignerKey({ network: "mainnet", resource: GCP, pubkey: GCP_PUB })).not.toThrow();
    expect(() => assertActiveSignerKey({ network: "mainnet", resource: GCP, pubkey: new Uint8Array(32).fill(4) })).toThrow(/not the active signer key gcp/);
    expect(() => assertActiveSignerKey(k)).toThrow(/not the active signer key gcp/);
    expect(() => assertActiveSignerKey({ ...k, network: "testnet" })).not.toThrow();
    const none = tmp({ ...K, active: { cosigner: "aliyun-softkey", signer: null } });
    expect(() => assertActiveSignerKey(k, { VITEST: "1" }, { inventoryPath: none })).toThrow(/no active signer key is defined/);
    const inv = tmp({ ...K, active: { cosigner: "aliyun-softkey", signer: "s" }, s: { role: "active", keyVersionName: k.resource, pubkeyB64: Buffer.from(k.pubkey).toString("base64") } });
    expect(() => assertActiveSignerKey(k, { VITEST: "1" }, { inventoryPath: inv })).not.toThrow();
    expect(() => assertActiveSignerKey({ ...k, pubkey: new Uint8Array(32).fill(5) }, { VITEST: "1" }, { inventoryPath: inv })).toThrow(/not the active signer key s/);
    expect(() => assertActiveSignerKey({ ...k, resource: AWS }, { VITEST: "1" }, { inventoryPath: inv })).toThrow(/backup key/);
  });
  it("R77-P3-1: MR_KEY_INVENTORY / MR_KEY_ORDER_DOC are refused on MainNet and in production; TestNet keeps them", () => {
    const inv = tmp(K);
    for (const env of [{ MR_KEY_INVENTORY: inv }, { MR_KEY_ORDER_DOC: "/x.md" }]) {
      expect(() => loadKeyOrder("mainnet", env)).toThrow(/refused on mainnet/);
      expect(() => loadKeyOrder("testnet", { ...env, NODE_ENV: "production" })).toThrow(/refused on mainnet \/ NODE_ENV=production/);
      expect(() => loadKeyOrder("testnet", env)).not.toThrow();
    }
    process.env.MR_KEY_INVENTORY = inv;
    try { expect(() => new CloudKmsBackend({ network: "mainnet", keyVersionName: GCP, pubkey: GCP_PUB, protectionLevel: "SOFTWARE", serviceAccountEmail: K.gcp.serviceAccountEmail })).toThrow(/refused on mainnet/); }
    finally { delete process.env.MR_KEY_INVENTORY; }
  });
  it("R79-P3-3: KeyOrderFiles are refused outside vitest and with NODE_ENV=production", () => {
    const inv = tmp(K);
    expect(() => loadKeyOrder("mainnet", {}, { inventoryPath: inv })).toThrow(/test-only seam/);
    expect(() => loadKeyOrder("testnet", { VITEST: "1", NODE_ENV: "production" }, { docPath: "/x.md" })).toThrow(/test-only seam/);
    expect(() => assertActiveSignerKey({ network: "mainnet", resource: GCP, pubkey: GCP_PUB }, {}, { inventoryPath: inv })).toThrow(/test-only seam/);
    expect(() => loadKeyOrder("mainnet", { VITEST: "1" }, { inventoryPath: inv })).not.toThrow();
  });
  it("R79-P3-2: mr-piv-sign builds its backend only via MR_PIV_BACKEND / MR_KMS_CONFIG -> cloudKmsFromConfig", async () => {
    const { backendFromEnv } = await import("../src/piv/backend-from-env.js");
    const cfg = path.join(__dirname, "../../../deploy/gcp/cloudkms.mainnet.json");
    const ck = JSON.parse(readFileSync(cfg, "utf8"));
    expect(backendFromEnv("mainnet", { MR_PIV_BACKEND: "cloudkms", MR_KMS_CONFIG: cfg }).kind).toBe("cloudkms");
    expect(() => backendFromEnv("mainnet", { MR_KMS_CONFIG: cfg })).toThrow(/only "cloudkms"/);
    expect(() => backendFromEnv("mainnet", { MR_PIV_BACKEND: "software", MR_KMS_CONFIG: cfg })).toThrow(/only "cloudkms"/);
    expect(() => backendFromEnv("testnet", { MR_PIV_BACKEND: "cloudkms", MR_KMS_CONFIG: cfg })).toThrow(/is for mainnet/);
    expect(() => backendFromEnv("mainnet", { MR_PIV_BACKEND: "cloudkms", MR_KMS_CONFIG: "/nonexistent.json" })).toThrow(/unreadable/);
    const bad = tmp({ ...ck, role: "backup" });
    expect(() => backendFromEnv("mainnet", { MR_PIV_BACKEND: "cloudkms", MR_KMS_CONFIG: bad })).toThrow(/role backup/);
    const other2 = tmp({ ...ck, pubkeyB64: Buffer.alloc(32, 7).toString("base64") });
    expect(() => backendFromEnv("mainnet", { MR_PIV_BACKEND: "cloudkms", MR_KMS_CONFIG: other2 })).toThrow(/not the active signer key gcp/);
    const src = readFileSync(path.join(__dirname, "../src/piv/stdio-main.ts"), "utf8");
    expect(src).toMatch(/runStdio\(cfg, backendFromEnv\(/);
  });
  it("R77-P3-5: backup lines are read from bulleted as well as numbered list items", () => {
    expect(backupResourcesFromDoc("- AWS `alias/x` backup\n* `arn:aws:kms:us-east-1:000000000000:key/y` (backup)\n1) `alias/z` backup\nprose `alias/w` backup")).toEqual(["alias/x", "arn:aws:kms:us-east-1:000000000000:key/y", "alias/z"]);
  });
  it("MainNet verifier platform: aliyun-softkey only (awskms without a platform, option C and aws are refused)", () => {
    const drpc = { host: "algorand.drpc.org", operator: "drpc", kind: "blockscan-full" as const, baseUrl: "https://algorand.drpc.org" };
    const mn = { network: "mainnet", providers: [{ operator: "nodely" }] };
    const aw = { region: "us-east-1", keyArn: "arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000000", roleName: "v" };
    expect(() => assertPlatformConfig({ awskms: aw, providers: [drpc] }, mn)).toThrow(/only active co-signer is aliyun-softkey/);
    expect(() => assertPlatformConfig({ providers: [drpc] }, mn)).toThrow(/only active co-signer is aliyun-softkey/);
    expect(() => assertPlatformConfig({ platform: "aliyun-softkey", softkey: { allowMainnet: true }, providers: [drpc] }, mn)).not.toThrow();
  });
});

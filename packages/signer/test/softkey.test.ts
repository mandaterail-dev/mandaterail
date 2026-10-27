/** rev 24 §24.8: the verifier's software Ed25519 key file (platform aliyun-softkey); no key material is printed. */
import { describe, expect, it } from "vitest";
import { generateKeyPairSync, randomBytes, createPublicKey } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync, existsSync } from "node:fs";
import { execFileSync, spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import path from "node:path";
import { encodeAttestation, isoSeconds, verifyAttestation, loadIntegrityManifest, VERIFIER_SOFTKEY_PINS } from "@mandaterail/storage";
import { GENESIS_PINS } from "../src/config.js";
import { SoftkeyFileEd25519Backend, softkeyGate } from "../src/piv/softkey-file.js";
import { assertPlatformConfig } from "../src/verifier/main.js";

const att = (network: "testnet" | "mainnet") => encodeAttestation({ v: 1, network, genesisHash: GENESIS_PINS[network], keyId: "0".repeat(32), store: "s", spendId: "a", txId: "A".repeat(52), sender: "A".repeat(58),
  groupId: "", firstValid: 1, lastValid: 2, round: 20, nonce: randomBytes(32).toString("base64url"), expiry: isoSeconds(Date.now() + 60_000), observations: [] });

function credDir() {
  const { privateKey } = generateKeyPairSync("ed25519");
  const d = mkdtempSync(path.join(tmpdir(), "mr-softkey-"));
  writeFileSync(path.join(d, "cosign.key"), privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
  const pub = new Uint8Array(createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(12));
  return { d, pub };
}

describe("rev 24 softkey verifier backend", () => {
  it("TestNet: reads $CREDENTIALS_DIRECTORY/cosign.key, pubkey must match the DB pin, signature verifies against it", async () => {
    const { d, pub } = credDir();
    const be = new SoftkeyFileEd25519Backend({ network: "testnet", pubkey: pub, manifestAllows: true }, { CREDENTIALS_DIRECTORY: d });
    expect(be.kind).toBe("softkey-file");
    expect(Buffer.from(await be.publicKey()).equals(Buffer.from(pub))).toBe(true);
    const m = att("testnet");
    const sig = await be.sign(m);
    expect(verifyAttestation(m, sig, pub)).toBe(true);
    await expect(be.sign(att("mainnet"))).rejects.toThrow(/refusing a message for mainnet/);
    await expect(be.sign(Buffer.from("raw bytes"))).rejects.toThrow(/not an attestation/);
    const other = credDir();
    expect(() => new SoftkeyFileEd25519Backend({ network: "testnet", pubkey: other.pub, manifestAllows: true }, { CREDENTIALS_DIRECTORY: d })).toThrow(/differs from cosignerPubkeyB64/);
  });
  it("needs systemd LoadCredential (no CREDENTIALS_DIRECTORY = refuse); bare credential names only; errors never include key bytes", () => {
    const { d, pub } = credDir();
    expect(() => new SoftkeyFileEd25519Backend({ network: "testnet", pubkey: pub, manifestAllows: true }, {})).toThrow(/CREDENTIALS_DIRECTORY/);
    expect(() => new SoftkeyFileEd25519Backend({ network: "testnet", pubkey: pub, manifestAllows: true, credentialName: "../x" }, { CREDENTIALS_DIRECTORY: d })).toThrow(/bare credential name/);
    writeFileSync(path.join(d, "bad.key"), "-----BEGIN PRIVATE KEY-----\nnotakey\n-----END PRIVATE KEY-----\n");
    let msg = "";
    try { new SoftkeyFileEd25519Backend({ network: "testnet", pubkey: pub, manifestAllows: true, credentialName: "bad.key" }, { CREDENTIALS_DIRECTORY: d }); } catch (e) { msg = (e as Error).message; }
    expect(msg).toMatch(/not a PKCS#8 PEM/);
    expect(msg).not.toMatch(/notakey|BEGIN/);
  });
  it("MainNet gate: refused unless the manifest pin AND softkey.allowMainnet; the shipped manifest pins mainnet=false", () => {
    const { d, pub } = credDir();
    expect(VERIFIER_SOFTKEY_PINS).toEqual({ mainnet: false, testnet: true });
    expect(loadIntegrityManifest({}).verifierSoftkey).toEqual({ mainnet: false, testnet: true });
    expect(() => softkeyGate("mainnet", true, false)).toThrow(/manifest pins verifierSoftkey.mainnet = false/);
    expect(() => softkeyGate("mainnet", undefined, true)).toThrow(/allowMainnet is not set/);
    expect(() => softkeyGate("testnet", undefined, false)).toThrow(/verifierSoftkey.testnet = false/);
    expect(() => new SoftkeyFileEd25519Backend({ network: "mainnet", pubkey: pub, allowMainnet: true, manifestAllows: false }, { CREDENTIALS_DIRECTORY: d })).toThrow(/manifest pins/);
    // both set (a future manifest + internal reviewer run): constructs and signs MainNet messages only
    const be = new SoftkeyFileEd25519Backend({ network: "mainnet", pubkey: pub, allowMainnet: true, manifestAllows: true }, { CREDENTIALS_DIRECTORY: d });
    expect(be.gatePassed).toBe("mainnet");
  });
  it("platform aliyun-softkey: needs softkey and no awskms/ykcs11; MainNet providers dRPC only, disjoint from the signer", () => {
    const drpc = { host: "algorand.drpc.org", operator: "drpc", kind: "blockscan-full" as const, baseUrl: "https://algorand.drpc.org" };
    const mn = { network: "mainnet", providers: [{ operator: "nodely" }, { operator: "getblock" }] };
    expect(() => assertPlatformConfig({ platform: "aliyun-softkey", softkey: {}, providers: [drpc] }, mn)).not.toThrow();
    expect(() => assertPlatformConfig({ platform: "aliyun-softkey", providers: [drpc] }, mn)).toThrow(/needs softkey/);
    expect(() => assertPlatformConfig({ platform: "aliyun", softkey: {}, providers: [drpc] }, mn)).toThrow(/only for platform aliyun-softkey/);
    expect(() => assertPlatformConfig({ platform: "aliyun-softkey", softkey: {}, providers: [{ ...drpc, operator: "getblock" }] }, mn)).toThrow(/dRPC only/);
    expect(() => assertPlatformConfig({ platform: "aliyun-softkey", softkey: {}, providers: [drpc] }, { network: "mainnet", providers: [{ operator: "drpc" }] })).toThrow(/also pinned by the signer/);
  });
});

describe("rev 24 softkey deploy files (static + local keygen run; nothing applied)", () => {
  const D = path.resolve(__dirname, "../../../deploy");
  it("render aliyun-softkey: egress = common hosts only (dRPC, no AWS, no KMS endpoint, no signer operators)", () => {
    const T = mkdtempSync(path.join(tmpdir(), "softkey-render-"));
    execFileSync("sh", [path.join(D, "verifier/render-platform.sh"), "aliyun-softkey", T]);
    const hosts = readFileSync(path.join(T, "egress-hosts.conf"), "utf8").split("\n").map((l) => l.replace(/#.*/, "").trim()).filter(Boolean);
    expect(hosts).toContain("algorand.drpc.org");
    expect(hosts.filter((h) => /amazonaws|aliyuncs|kms|getblock|nodely|blockdaemon|algonode/.test(h))).toEqual([]);
    expect(readFileSync(path.join(T, "nftables.conf"), "utf8")).toContain("define KMS_VPCE = { 127.0.0.2 }\n");
  });
  it("keygen: 0600 PKCS#8 key in a 0700 dir, raw 32-byte pubkey exported, never overwrites, private key never printed; backend accepts it", async () => {
    const T = mkdtempSync(path.join(tmpdir(), "softkey-gen-"));
    const dir = path.join(T, "k");
    const me = execFileSync("id", ["-un"], { encoding: "utf8" }).trim();
    const out = execFileSync("sh", [path.join(D, "verifier/mr-verifier-keygen.sh")], { env: { ...process.env, MR_KEY_DIR: dir, MR_KEY_OWNER: me }, encoding: "utf8" });
    expect(out).not.toMatch(/PRIVATE KEY/);
    expect(statSync(path.join(dir, "cosign.key")).mode & 0o777).toBe(0o600);
    expect(statSync(dir).mode & 0o777).toBe(0o700);
    const pubB64 = readFileSync(path.join(dir, "cosign.pub"), "utf8").trim();
    expect(Buffer.from(pubB64, "base64")).toHaveLength(32);
    expect(out).toContain(`cosignerPubkeyB64=${pubB64}`);
    const before = readFileSync(path.join(dir, "cosign.key"));
    execFileSync("sh", [path.join(D, "verifier/mr-verifier-keygen.sh")], { env: { ...process.env, MR_KEY_DIR: dir, MR_KEY_OWNER: me }, stdio: "pipe" });
    expect(readFileSync(path.join(dir, "cosign.key")).equals(before)).toBe(true);
    const run = (...a: string[]) => spawnSync("sh", [path.join(D, "verifier/mr-verifier-keygen.sh"), ...a], { env: { ...process.env, MR_KEY_DIR: dir, MR_KEY_OWNER: me }, encoding: "utf8" });
    expect(run("--check").status).toBe(0);
    // R67 nit: a crash between the two renames left no pub; the rerun re-exports the same pub
    rmSync(path.join(dir, "cosign.pub"));
    const re = run();
    expect(re.status).toBe(0);
    expect(re.stdout + re.stderr).not.toMatch(/PRIVATE KEY/);
    expect(readFileSync(path.join(dir, "cosign.pub"), "utf8").trim()).toBe(pubB64);
    // R67-P3-6: fail closed on mode, owner and symlink
    chmodSync(path.join(dir, "cosign.key"), 0o644);
    expect(run("--check").status).toBe(1);
    expect(run().status).toBe(1);
    chmodSync(path.join(dir, "cosign.key"), 0o600);
    expect(spawnSync("sh", [path.join(D, "verifier/mr-verifier-keygen.sh"), "--check"], { env: { ...process.env, MR_KEY_DIR: dir, MR_KEY_OWNER: "root" }, encoding: "utf8" }).status).toBe(me === "root" ? 0 : 1);
    const ldir = path.join(T, "l"); mkdirSync(ldir, { mode: 0o700 });
    symlinkSync(path.join(dir, "cosign.key"), path.join(ldir, "cosign.key"));
    expect(spawnSync("sh", [path.join(D, "verifier/mr-verifier-keygen.sh"), "--check"], { env: { ...process.env, MR_KEY_DIR: ldir, MR_KEY_OWNER: me }, encoding: "utf8" }).status).toBe(1);
    expect(run("--check").status).toBe(0);
    const pub = new Uint8Array(Buffer.from(pubB64, "base64"));
    const be = new SoftkeyFileEd25519Backend({ network: "testnet", pubkey: pub, manifestAllows: true }, { CREDENTIALS_DIRECTORY: dir });
    const m = att("testnet");
    expect(verifyAttestation(m, await be.sign(m), pub)).toBe(true);
  });
  it("units: LoadCredential delivery, key dir hidden from the verifier, first-boot keygen offline; option C marked unused", () => {
    const dropin = readFileSync(path.join(D, "verifier/mr-verifier.service.d/softkey.conf"), "utf8");
    expect(dropin).toMatch(/^LoadCredential=cosign\.key:\/var\/lib\/mr-verifier-key\/cosign\.key$/m);
    expect(dropin).toMatch(/^InaccessiblePaths=\/var\/lib\/mr-verifier-key$/m);
    expect(dropin).toMatch(/^Requires=mr-verifier-keygen\.service$/m);
    const kg = readFileSync(path.join(D, "verifier/mr-verifier-keygen.service"), "utf8");
    expect(kg).not.toMatch(/ConditionPathExists/); // runs every boot: checks + re-exports the pub
    expect(kg).toMatch(/^Environment=.*MR_KEY_OWNER=root$/m); // R67-P3-5
    expect(kg).toMatch(/^OnFailure=mr-verifier-page@%n\.service$/m);
    expect(dropin).toMatch(/^ExecStartPre=\+\/opt\/mr-verifier\/current\/deploy\/verifier\/mr-verifier-keygen\.sh --check$/m); // R67-P3-6
    for (const u of ["mr-gcp-token.service", "mr-verifier-page@.service"]) {
      expect(readFileSync(path.join(D, "verifier", u), "utf8")).toMatch(/^InaccessiblePaths=-\/var\/lib\/mr-verifier-key$/m);
    }
    expect(kg).toMatch(/^PrivateNetwork=yes$/m);
    // R76-P3-6: the option C (AWS Roles Anywhere) files are gone
    for (const f of ["aws-rolesanywhere", "verifier/mr-aws-rolesanywhere.service", "verifier/rolesanywhere.env.example"]) expect(existsSync(path.join(D, f)), f).toBe(false);
  });
});

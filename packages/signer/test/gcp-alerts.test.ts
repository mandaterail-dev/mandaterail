import { existsSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const tf = readFileSync(new URL("../../../deploy/gcp/alerts/main.tf", import.meta.url), "utf8");
const readme = readFileSync(new URL("../../../deploy/gcp/README.md", import.meta.url), "utf8");

describe("R76-P3-6 no AWS co-signer", () => {
  it("the AWS verifier design and its platform files are removed; the aliyun nftables keeps the uid-scoped IMDS rule", () => {
    const nft = readFileSync(new URL("../../../deploy/verifier/nftables.conf", import.meta.url), "utf8");
    for (const f of ["deploy/aws/main.tf", "deploy/aws/forwarder", "deploy/verifier/platform/aws.nft", "deploy/verifier/platform/aliyun-aws-kms.nft"]) expect(existsSync(new URL(`../../../${f}`, import.meta.url)), f).toBe(false);
    expect(nft).toContain('meta skuid "mr-verifier" ip daddr $IMDS tcp dport 80 accept');
  });
});

describe("R48-P2-2 GCP alerts config", () => {
  it("covers every required event", () => {
    for (const k of ["every-asymmetric-sign", "sign-not-by-signer-vm", "act-as-or-attach-sa", "key-version-lifecycle", "audit-config-and-iam", "iap-oslogin-admin"]) expect(tf).toContain(`${k} = {`);
    for (const m of ["AsymmetricSign", "iam.serviceAccounts.actAs", "setServiceAccount", "DestroyCryptoKeyVersion", "RestoreCryptoKeyVersion", "UpdateCryptoKeyVersion", "auditConfigDeltas", "SetIamPolicy", "iap.googleapis.com", "compute.osAdminLogin"]) expect(tf).toContain(m);
  });
  it("pages outside GCP via webhook and Pub/Sub, enables DATA_READ, no committed topic", () => {
    expect(tf).toMatch(/type\s+= "pubsub"/);
    expect(tf).not.toMatch(/variable "ntfy_url"/); // R49-P3: the URL is only in Secret Manager
    // R49-P2-1: reserved static internal IP + callerNetwork, never the generic gce-internal-ip
    const f = tf.split("\n").filter((l) => /^\s*filter\s*=/.test(l)).join("\n");
    expect(f).not.toContain("gce-internal-ip");
    expect(f).toContain("callerIp!=\\\"${google_compute_address.signer.address}");
    expect(f).toContain("callerNetwork!=");
    expect(tf).toMatch(/address_type\s+= "INTERNAL"/);
    expect(readFileSync(new URL("../../../deploy/gcp/alerts/forwarder/package-lock.json", import.meta.url), "utf8")).toContain('"lockfileVersion"');
    expect(tf).toContain("google_logging_project_sink");
    expect(tf).toMatch(/cloudkms\.googleapis\.com"[\s\S]*DATA_READ/);
    expect(tf).not.toMatch(/ntfy\.sh\/[A-Za-z0-9_-]+/);
    expect(readme).not.toContain("audit chain count");
    expect(readme).toContain("Cloud Identity organization");
  });
});

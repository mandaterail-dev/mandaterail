/** Host configs (rev 12): systemd units verify, nftables parses, usbguard/udev pin the YubiKey serial. */
import { describe, expect, it } from "vitest";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const D = path.resolve(__dirname, "../../../deploy");
const has = (b: string) => spawnSync("sh", ["-c", `command -v ${b}`]).status === 0;
const sudoNft = existsSync("/usr/sbin/nft") && spawnSync("sudo", ["-n", "true"]).status === 0;

describe("host configs", () => {
  it.skipIf(!has("systemd-analyze"))("systemd-analyze verify: no unknown keys / errors in the units", () => {
    const T = mkdtempSync(path.join(tmpdir(), "units-"));
    for (const u of ["signer/host/mr-signer.service", "verifier/mr-verifier.service", "signer/mr-piv-sign@.service", "signer/mr-piv-sign.socket", "gcp/mr-signer.service", "gcp/mr-piv-sign@.service", "verifier/mr-egress-refresh.service", "verifier/mr-egress-refresh.timer", "verifier/mr-gcp-token.service", "verifier/mr-gcp-token.timer", "verifier/mr-verifier-page@.service"]) {
      const out = u.startsWith("gcp/") ? `gcp-${path.basename(u)}` : path.basename(u).replace("@.service", "@x.service");
      const s = readFileSync(path.join(D, u), "utf8").replace(/^ExecStart=.*$/m, "ExecStart=/bin/true").replace(/^(EnvironmentFile|LoadCredentialEncrypted)=.*$/gm, "");
      writeFileSync(path.join(T, out), s);
    }
    const r = spawnSync("systemd-analyze", ["verify", "--man=no", ...["mr-signer.service", "mr-verifier.service", "mr-piv-sign@.service", "mr-piv-sign.socket", "gcp-mr-signer.service", "gcp-mr-piv-sign@.service", "mr-egress-refresh.service", "mr-egress-refresh.timer", "mr-gcp-token.service", "mr-gcp-token.timer", "mr-verifier-page@x.service"].map((x) => path.join(T, x))], { encoding: "utf8", timeout: 60_000 });
    const out = `${r.stdout}${r.stderr}`;
    expect(out).not.toMatch(/Unknown key|Unknown section|Invalid|Failed to parse|bad-setting/i);
  }, 90_000);

  it.skipIf(!sudoNft)("signer + verifier nftables.conf parse (nft -c, users mapped to existing ones)", () => {
    for (const c of ["signer/host/nftables.conf", "verifier/nftables.conf", "gcp/nftables.conf"]) {
      const s = readFileSync(path.join(D, c), "utf8").replace(/"systemd-resolve"|"_chrony"/g, '"root"').replace(/"mr-(signer|verifier|piv)"/g, '"nobody"').replace(/\{ "nobody", "root" \}/g, '{ "nobody", "daemon" }');
      const f = path.join(mkdtempSync(path.join(tmpdir(), "nft-")), "n.conf");
      writeFileSync(f, s);
      execFileSync("sudo", ["-n", "/usr/sbin/nft", "-c", "-f", f]);
      expect(s).toMatch(/policy drop;[\s\S]*policy drop;[\s\S]*policy drop;/);
    }
  });

  it("R46-P3: wg0 egress is per-uid on both hosts; the verifier ruleset names only mr-verifier; unit comments are accurate", () => {
    const sg = readFileSync(path.join(D, "signer/host/nftables.conf"), "utf8"), vf = readFileSync(path.join(D, "verifier/nftables.conf"), "utf8");
    for (const s of [sg, vf]) expect(s).not.toMatch(/oifname "wg0" accept/);
    expect(sg).toMatch(/oifname "wg0" meta skuid "mr-signer" accept/);
    expect(vf).toMatch(/oifname "wg0" meta skuid "mr-verifier" accept/);
    expect(vf).not.toMatch(/mr-signer/);
    const vu = readFileSync(path.join(D, "verifier/mr-verifier.service"), "utf8");
    expect(vu).not.toMatch(/providers, B2/);
    expect(vu).toMatch(/pid file does not mean synced/);
  });

  it("USB: usbguard default-rejects and allows the YubiKey only by serial; udev + unit agree", () => {
    const ug = readFileSync(path.join(D, "signer/host/usbguard-rules.conf"), "utf8");
    expect(ug.trim().split("\n").at(-1)).toBe("reject");
    for (const l of ug.split("\n").filter((x) => /^allow id 1050:/.test(x))) expect(l).toMatch(/serial "PINNED_SERIAL"/);
    expect(readFileSync(path.join(D, "signer/70-mr-yubikey.rules"), "utf8")).toMatch(/ATTRS\{serial\}=="PINNED_SERIAL".*TAG\+="systemd"/);
    const svc = readFileSync(path.join(D, "signer/mr-piv-sign@.service"), "utf8");
    expect(svc).toMatch(/BindsTo=dev-mr\\x2dyubikey\.device/);
    expect(svc).toMatch(/DeviceAllow=\/dev\/mr-yubikey rw/);
    expect(readFileSync(path.join(D, "signer/host/chrony.conf"), "utf8")).toMatch(/authselectmode require[\s\S]*minsources 2/);
  });

  it("rev 15 GCP: helper has no USB/PIN, network only to MDS/PGA/resolver; MDS token port only for mr-piv/root; IAP-only ingress", () => {
    const h = readFileSync(path.join(D, "gcp/mr-piv-sign@.service"), "utf8");
    expect(h).not.toMatch(/yubikey|LoadCredentialEncrypted|PrivateNetwork=yes/i);
    expect(h).toMatch(/IPAddressDeny=any\nIPAddressAllow=127\.0\.0\.53\/32 169\.254\.169\.254\/32 199\.36\.153\.8\/30/);
    const n = readFileSync(path.join(D, "gcp/nftables.conf"), "utf8");
    expect(n).toMatch(/ip daddr \$MDS tcp dport 80 meta skuid \{ "mr-piv", "root" \} accept/);
    expect(n).not.toMatch(/skuid "mr-signer"[^\n]*\$MDS|\$MDS[^\n]*"mr-signer"/);
    expect(n).toMatch(/ip saddr \$IAP_RANGE tcp dport \{ 22, \$SIGNER_PORT \}/);
    expect(n).not.toMatch(/wg0|WG_PORT/);
    expect(readFileSync(path.join(D, "gcp/mr-signer.service"), "utf8")).not.toMatch(/wg-quick/);
    const ex = JSON.parse(readFileSync(path.join(D, "gcp/cloudkms.example.json"), "utf8"));
    expect(ex.keyVersionName).toMatch(/cryptoKeyVersions\/1$/);
    expect(ex.protectionLevel).toBe("SOFTWARE");
  });

  it("R51-P3-1: verifier HTTPS allowlist names exactly the needed hosts; refresh adds resolved addresses; other 443 denied", () => {
    const hosts = readFileSync(path.join(D, "verifier/egress-hosts.conf"), "utf8").split("\n").map((l) => l.replace(/#.*/, "").trim()).filter(Boolean);
    expect(hosts).toEqual(["kms-vpc.us-east-1.aliyuncs.com", "sts.googleapis.com", "iamcredentials.googleapis.com", "logging.googleapis.com", "algorand.drpc.org", "ntfy.sh", "hc-ping.com", "s3.<b2-region>.backblazeb2.com"]);
    const vf = readFileSync(path.join(D, "verifier/nftables.conf"), "utf8");
    expect(vf).toMatch(/@https_allowed6 tcp dport 443 accept\n\s+#[^\n]*\n\s+tcp dport 443 log prefix "mr-https-deny "[^\n]*drop/);
    const T = mkdtempSync(path.join(tmpdir(), "egr-"));
    const nft = path.join(T, "nft"); writeFileSync(nft, `#!/bin/sh\necho "ARGS $@" >> ${T}/calls\ncat >> ${T}/calls\n`, { mode: 0o755 });
    const bin = path.join(T, "bin"); mkdirSync(bin);
    writeFileSync(path.join(bin, "getent"), `#!/bin/sh\ncase "$1$2" in ahostsv4a) echo "192.0.2.1 STREAM a";; ahostsv4b) echo "192.0.2.1 STREAM b"; echo "192.0.2.7 STREAM b";; ahostsv6b) echo "2001:db8::1 STREAM b";; esac\nexit 0\n`, { mode: 0o755 });
    const run = (h: string) => { writeFileSync(path.join(T, "h.conf"), h); return spawnSync("sh", [path.join(D, "verifier/mr-egress-refresh.sh")], { env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, MR_EGRESS_HOSTS: path.join(T, "h.conf"), MR_NFT: nft }, encoding: "utf8" }); };
    expect(run("# c\na\nb\n").status).toBe(0);
    // R52-P2-1: ONE `nft -f -` batch per run: add + destroy + add (resets the expiry atomically), deduplicated
    expect(readFileSync(path.join(T, "calls"), "utf8")).toBe(["ARGS -f -",
      ...["add", "destroy", "add"].map((v) => `${v} element inet mr https_allowed4 { 192.0.2.1, 192.0.2.7 }`),
      ...["add", "destroy", "add"].map((v) => `${v} element inet mr https_allowed6 { 2001:db8::1 }`), ""].join("\n"));
    expect(readFileSync(path.join(D, "verifier/mr-egress-refresh.sh"), "utf8")).toMatch(/^set -euf$/m);
    const pg = readFileSync(path.join(D, "verifier", "mr-verifier-page@.service"), "utf8");
    const ex = pg.split("\n").find((l) => l.startsWith("ExecStart="))!;
    expect(ex).toMatch(/curl -K - /); // R53-P3-3: URL+topic via stdin config
    expect(ex).not.toMatch(/(^|[^$])\$\{?MR_NTFY_TOPIC/); // only $$-escaped (sh-side, builtin printf), never systemd-expanded into argv
    for (const u of ["mr-egress-refresh.service", "mr-gcp-token.service"]) expect(readFileSync(path.join(D, "verifier", u), "utf8")).toMatch(/^OnFailure=mr-verifier-page@%n\.service$/m);
    const bad = run("a\ns3.<b2-region>.backblazeb2.com\n");
    expect(bad.status).not.toBe(0);
    expect(bad.stderr).toMatch(/unfilled/);
    const u = readFileSync(path.join(D, "verifier/mr-verifier.service"), "utf8");
    expect(u).toMatch(/^After=.*mr-egress-refresh\.service/m);
  });

  it.skipIf(!sudoNft || !has("unshare"))("R52-P2-1 (live nft, private netns): a refresh resets the expiry of existing elements and keeps the others", () => {
    const T = mkdtempSync(path.join(tmpdir(), "egl-"));
    const bin = path.join(T, "bin"); mkdirSync(bin);
    writeFileSync(path.join(bin, "getent"), `#!/bin/sh\n[ "$1" = ahostsv4 ] && echo "192.0.2.1 STREAM $2"\nexit 0\n`, { mode: 0o755 });
    writeFileSync(path.join(T, "h.conf"), "kms.example\n");
    writeFileSync(path.join(T, "t.sh"), [
      "set -e", "nft add table inet mr",
      "nft 'add set inet mr https_allowed4 { type ipv4_addr; flags interval, timeout; timeout 2h; }'",
      "nft 'add set inet mr https_allowed6 { type ipv6_addr; flags interval, timeout; timeout 2h; }'",
      "nft 'add element inet mr https_allowed4 { 192.0.2.1 timeout 5s, 198.51.100.9 }'",
      `PATH=${bin}:$PATH MR_EGRESS_HOSTS=${T}/h.conf MR_NFT=/usr/sbin/nft sh ${path.join(D, "verifier/mr-egress-refresh.sh")} >/dev/null`,
      "nft list set inet mr https_allowed4", ""].join("\n"));
    const out = execFileSync("sudo", ["-n", "unshare", "-n", "sh", path.join(T, "t.sh")], { encoding: "utf8" });
    expect(out).toMatch(/192\.0\.2\.1 expires 1h59m/); // was 5 s: reset to the set's 2 h
    expect(out).toMatch(/198\.51\.100\.9 expires/); // untouched element kept
  });

  it("R63-P3e / rev 24: per-platform render (aliyun | aliyun-softkey; R76-P3-6 removed aws / aliyun-aws-kms); the checked-in copies are the aliyun render", () => {
    const hostsOf = (f: string) => readFileSync(f, "utf8").split("\n").map((l) => l.replace(/#.*/, "").trim()).filter(Boolean);
    const common = hostsOf(path.join(D, "verifier/platform/common.hosts"));
    const want: Record<string, { imds: string; hosts: string[] }> = {
      aliyun: { imds: "100.100.100.200", hosts: ["kms-vpc.us-east-1.aliyuncs.com"] },
      "aliyun-softkey": { imds: "100.100.100.200", hosts: [] },
    };
    for (const [p, w] of Object.entries(want)) {
      const T = mkdtempSync(path.join(tmpdir(), `plat-${p}-`));
      execFileSync("sh", [path.join(D, "verifier/render-platform.sh"), p, T]);
      const n = readFileSync(path.join(T, "nftables.conf"), "utf8");
      expect(n).toContain(`define IMDS = ${w.imds}\n`);
      expect(n.match(/^define IMDS/gm)).toHaveLength(1);
      expect(n.match(/^define KMS_VPCE/gm)).toHaveLength(1);
      expect(hostsOf(path.join(T, "egress-hosts.conf"))).toEqual([...w.hosts, ...common]);
      if (p === "aliyun") {
        expect(n).toBe(readFileSync(path.join(D, "verifier/nftables.conf"), "utf8"));
        expect(readFileSync(path.join(T, "egress-hosts.conf"), "utf8")).toBe(readFileSync(path.join(D, "verifier/egress-hosts.conf"), "utf8"));
      }
      if (sudoNft) {
        const f = path.join(T, "c.conf");
        writeFileSync(f, n.replace(/"systemd-resolve"|"_chrony"/g, '"root"').replace(/"mr-verifier"/g, '"nobody"'));
        execFileSync("sudo", ["-n", "/usr/sbin/nft", "-c", "-f", f]);
      }
    }
    for (const p of ["gcp", "aws", "aliyun-aws-kms"]) expect(spawnSync("sh", [path.join(D, "verifier/render-platform.sh"), p, tmpdir()]).status).toBe(2);
  });
});

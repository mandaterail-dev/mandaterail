/** rev 22: deploy/aliyun (verifier on its own Alibaba ECS): static checks of the OpenTofu config (no account touched). */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import path from "node:path";

const D = path.resolve(__dirname, "../../../deploy/aliyun");
const main = readFileSync(path.join(D, "main.tf"), "utf8");
const versions = readFileSync(path.join(D, "versions.tf"), "utf8");
const block = (type: string, name: string) => {
  const i = main.indexOf(`resource "${type}" "${name}" {`);
  expect(i, `${type}.${name}`).toBeGreaterThanOrEqual(0);
  let depth = 0, j = main.indexOf("{", i);
  for (let k = j; k < main.length; k++) { if (main[k] === "{") depth++; else if (main[k] === "}" && --depth === 0) return main.slice(i, k + 1); }
  throw new Error("unterminated");
};

describe("deploy/aliyun (rev 22)", () => {
  it("own instance in its own VPC (never the app ECS), hardened metadata, EIP pinned and undeletable", () => {
    expect(main).not.toMatch(/8\.221\.97\.26|i-0xib0he8pff28t6jlwb1|vpc-0xix4oqqgwu09qizdgfsz/);
    const inst = block("alicloud_instance", "verifier");
    expect(inst).toMatch(/vswitch_id\s+= alicloud_vswitch\.a\.id/);
    expect(inst).toMatch(/http_tokens\s+= "required"/);
    expect(inst).toMatch(/http_put_response_hop_limit = 1/);
    expect(inst).toMatch(/role_name\s+= alicloud_ram_role\.verifier\.role_name/);
    expect(block("alicloud_eip_address", "verifier")).toMatch(/prevent_destroy = true/);
    expect(block("alicloud_security_group_rule", "wg")).toMatch(/51820\/51820/);
    expect(main).not.toMatch(/port_range\s+= "22\/22"/);
  });
  it("KMS key only with an approved KMS instance; prevent_destroy + deletion protection; sign pinned to the VPC and EIP", () => {
    const k = block("alicloud_kms_key", "cosign");
    expect(k).toMatch(/count\s+= var\.kms_instance_id == "" \? 0 : 1/);
    expect(k).toMatch(/prevent_destroy = true/);
    expect(k).toMatch(/deletion_protection\s+= "Enabled"/);
    expect(k).toMatch(/key_usage\s+= "SIGN\/VERIFY"/);
    const pol = block("alicloud_ram_policy", "sign");
    expect(pol).toMatch(/"kms:AsymmetricSign", "kms:GetPublicKey"/);
    expect(pol).toMatch(/"acs:SourceVpc" = \[alicloud_vpc\.v\.id\]/);
    expect(pol).toMatch(/NotIpAddress = \{ "acs:VpcSourceIp" = \["\$\{alicloud_instance\.verifier\.private_ip\}\/32"\] \}/); // R63-P3c
    expect(pol).not.toMatch(/"acs:SourceIp"/);
    for (const e of ["ScheduleKeyDeletion", "UpdateKmsInstanceBindVpc", "UpdateKeyStore", "CreateKeyVersion", "UpdateRotationPolicy", "DisconnectKmsInstance", "SetKeyPolicy"]) expect(main).toContain(`"${e}"`); // R63-P3a
    expect(main).not.toContain('"ScheduleKeyDelete"');
    expect(main).not.toMatch(/condition\s+= "n >= 0"/); // R63-P3b
  });
  it("ActionTrail (read events too) -> SLS -> alerts to ntfy and Healthchecks OUTSIDE Alibaba; capabilities only in encrypted state", () => {
    expect(block("alicloud_actiontrail_trail", "main")).toMatch(/event_rw\s+= "All"/);
    expect(block("alicloud_log_alert", "kms_sign")).toMatch(/AsymmetricSign/);
    for (const a of ["kms_sign", "admin"]) expect(block("alicloud_log_alert", a)).toMatch(/service_uri = var\.ntfy_webhook_url/);
    expect(block("alicloud_log_alert", "heartbeat")).toMatch(/service_uri = var\.healthchecks_url/);
    expect(main).toMatch(/variable "ntfy_webhook_url" \{[^}]*sensitive\s+= true/);
    expect(main).not.toMatch(/ntfy\.sh\/[A-Za-z0-9_-]+/);
    expect(versions).toMatch(/enforced = true/);
  });
});

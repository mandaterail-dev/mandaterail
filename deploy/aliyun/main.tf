# rev 24 (§24.8): the chosen verifier key is a software Ed25519 FILE generated on this instance at first boot
# (deploy/verifier/mr-verifier-keygen.service, platform aliyun-softkey). Keep kms_instance_id = "" (no KMS key, no
# KMS cost; the Oct 21 Alibaba KMS test showed Ed25519 keys cannot be created). The instance is the only cost.
# rev 22: the second verifier (mr-verifier, the co-signer) on Alibaba Cloud, on its OWN small ECS instance in its own
# VPC in US (Virginia) us-east-1 (same region as the app ECS, never on it). The signer stays on Google Cloud.
# NOT APPLIED. Nothing here is created without the owner's approval: the instance is a new paid resource, and an
# asymmetric KMS key needs a KMS instance (USD 500/mo subscription or ~USD 4.50/day pay-as-you-go), far above the
# $15/mo budget. See docs/ops/attested-release-signer.md §24 for the options. With kms_instance_id = "" (default)
# no KMS key is declared at all.
#   tofu init && tofu validate && tofu plan -var-file=... (no apply without the owner)

variable "region" {
  type    = string
  default = "us-east-1"
}
variable "zone" {
  type    = string
  default = "us-east-1a"
}
variable "account_id" { type = string }
variable "image_id" {
  type        = string
  description = "Debian 12 public image id in us-east-1 (pinned by id, not by name)"
}
variable "instance_type" {
  type        = string
  default     = "ecs.t6-c2m1.large"
  description = "2 vCPU burstable, 1 GiB (~USD 0.009/h on demand in us-east-1). ecs.t6-c4m1.large (0.5 GiB, ~0.005/h) is tight for node."
}
variable "kms_instance_id" {
  type        = string
  default     = ""
  description = "Existing software KMS instance (kst-...). Empty = no KMS key (needs the owner's approval + purchase first)."
}
variable "kms_key_spec" {
  type        = string
  default     = "Ed25519"
  description = "Ed25519 keeps the v12/v16 DB verification unchanged (listed for software-protected keys in the KMS key-spec doc; confirm in the console). EC_P256 would need a DB change."
  validation {
    condition     = contains(["Ed25519", "EC_P256"], var.kms_key_spec)
    error_message = "Ed25519 (preferred) or EC_P256 only."
  }
}
variable "ntfy_webhook_url" {
  type        = string
  sensitive   = true
  description = "ntfy.sh topic URL (outside Alibaba). A capability: TF_VAR_ntfy_webhook_url only; the state is encrypted."
}
variable "healthchecks_url" {
  type        = string
  sensitive   = true
  description = "Healthchecks.io ping URL (outside Alibaba): the daily heartbeat alert pings it; Healthchecks pages if it stops."
}
variable "state_passphrase" {
  type      = string
  sensitive = true
}
variable "sls_retention_days" {
  type    = number
  default = 400
}

provider "alicloud" { region = var.region }

locals {
  key_arn = var.kms_instance_id == "" ? "acs:kms:${var.region}:${var.account_id}:key/none" : "acs:kms:${var.region}:${var.account_id}:key/${alicloud_kms_key.cosign[0].id}"
}

# ---------------------------------------------------------------- network: its own VPC (acs:SourceVpc pins to it)
resource "alicloud_vpc" "v" {
  vpc_name   = "mr-verifier"
  cidr_block = "10.30.0.0/16"
}
resource "alicloud_vswitch" "a" {
  vswitch_name = "mr-verifier-a"
  vpc_id       = alicloud_vpc.v.id
  cidr_block   = "10.30.1.0/24"
  zone_id      = var.zone
}
resource "alicloud_security_group" "verifier" {
  security_group_name = "mr-verifier"
  vpc_id              = alicloud_vpc.v.id
  inner_access_policy = "Drop"
}
# ingress: WireGuard only (no SSH from the internet; admin via the WG tunnel / Workbench). Egress narrowed per uid by
# the host nftables (deploy/verifier/nftables.conf + egress-hosts.conf).
resource "alicloud_security_group_rule" "wg" {
  security_group_id = alicloud_security_group.verifier.id
  type              = "ingress"
  ip_protocol       = "udp"
  port_range        = "51820/51820"
  cidr_ip           = "0.0.0.0/0"
  policy            = "accept"
}
resource "alicloud_security_group_rule" "egress" {
  security_group_id = alicloud_security_group.verifier.id
  type              = "egress"
  ip_protocol       = "all"
  port_range        = "-1/-1"
  cidr_ip           = "0.0.0.0/0"
  policy            = "accept"
}

# ---------------------------------------------------------------- the co-signing key (only with an approved KMS instance)
resource "alicloud_kms_key" "cosign" {
  count                  = var.kms_instance_id == "" ? 0 : 1
  description            = "mr-verifier co-signing key"
  dkms_instance_id       = var.kms_instance_id
  key_spec               = var.kms_key_spec
  key_usage              = "SIGN/VERIFY"
  protection_level       = "SOFTWARE"
  pending_window_in_days = 30
  deletion_protection    = "Enabled"
  # a plan that would replace / destroy the co-signing key fails instead
  lifecycle { prevent_destroy = true }
}

# ---------------------------------------------------------------- instance RAM role: sign only from this VPC + EIP
resource "alicloud_ram_role" "verifier" {
  role_name            = "mr-verifier"
  max_session_duration = 3600
  assume_role_policy_document = jsonencode({
    Version = "1"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = ["ecs.aliyuncs.com"] }
    }]
  })
}
resource "alicloud_ram_policy" "sign" {
  policy_name = "mr-verifier-sign"
  policy_document = jsonencode({
    Version = "1"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["kms:AsymmetricSign", "kms:GetPublicKey"]
        Resource = [local.key_arn]
        # acs:SourceVpc is supported for KMS OpenAPI in US (Virginia); acs:VpcSourceIp pins the instance (R63-P3c)
        Condition = { StringEquals = { "acs:SourceVpc" = [alicloud_vpc.v.id] } }
      },
      {
        Effect    = "Deny"
        Action    = ["kms:*"]
        Resource  = ["*"]
        Condition = { StringNotEquals = { "acs:SourceVpc" = [alicloud_vpc.v.id] } }
      },
      {
        Effect   = "Deny"
        Action   = ["kms:AsymmetricSign"]
        Resource = ["*"]
        # R63-P3c: VPC-path calls carry acs:VpcSourceIp (the private address), not acs:SourceIp: pin the instance /32.
        # VERIFY LIVE (deny-sign from another VPC host and from the EIP) before relying on it.
        Condition = { NotIpAddress = { "acs:VpcSourceIp" = ["${alicloud_instance.verifier.private_ip}/32"] } }
      },
    ]
  })
}
resource "alicloud_ram_role_policy_attachment" "sign" {
  role_name   = alicloud_ram_role.verifier.role_name
  policy_name = alicloud_ram_policy.sign.policy_name
  policy_type = "Custom"
}

# ---------------------------------------------------------------- the instance: hardened metadata (tokens required)
resource "alicloud_instance" "verifier" {
  instance_name               = "mr-verifier"
  availability_zone           = var.zone
  instance_type               = var.instance_type
  credit_specification        = "Standard"
  image_id                    = var.image_id
  vswitch_id                  = alicloud_vswitch.a.id
  security_groups             = [alicloud_security_group.verifier.id]
  role_name                   = alicloud_ram_role.verifier.role_name
  instance_charge_type        = "PostPaid"
  internet_max_bandwidth_out  = 0 # public address = the EIP below only
  system_disk_category        = "cloud_essd_entry"
  system_disk_size            = 20
  system_disk_encrypted       = true
  http_endpoint               = "enabled"
  http_tokens                 = "required"
  http_put_response_hop_limit = 1
  deletion_protection         = true
  tags                        = { Name = "mr-verifier", "mr-role" = "verifier" }
}
# EIP: WireGuard ingress (the KMS sign path is pinned by acs:VpcSourceIp to the instance, R63-P3c); never released by a plan
resource "alicloud_eip_address" "verifier" {
  address_name         = "mr-verifier"
  internet_charge_type = "PayByTraffic"
  payment_type         = "PayAsYouGo"
  deletion_protection  = true
  lifecycle { prevent_destroy = true }
}
resource "alicloud_eip_association" "verifier" {
  allocation_id = alicloud_eip_address.verifier.id
  instance_id   = alicloud_instance.verifier.id
}

# ---------------------------------------------------------------- ActionTrail -> SLS -> alerts to ntfy (OUTSIDE Alibaba)
resource "alicloud_log_project" "trail" {
  project_name = "mr-verifier-trail-${var.account_id}"
  description  = "ActionTrail for the mr-verifier account (KMS AsymmetricSign + admin events)"
}
resource "alicloud_log_store" "trail" {
  project_name     = alicloud_log_project.trail.project_name
  logstore_name    = "actiontrail"
  retention_period = var.sls_retention_days
  shard_count      = 1
}
resource "alicloud_actiontrail_trail" "main" {
  trail_name      = "mr-verifier"
  event_rw        = "All" # AsymmetricSign is a read event: All, not Write
  trail_region    = "All"
  sls_project_arn = "acs:log:${var.region}:${var.account_id}:project/${alicloud_log_project.trail.project_name}"
  status          = "Enable"
}

locals {
  admin_events = [
    # KMS key + instance
    "DeleteKeyMaterial", "ScheduleKeyDeletion", "CancelKeyDeletion", "DisableKey", "EnableKey", "UpdateKeyDescription", "SetDeletionProtection",
    "CreateKey", "CreateAlias", "UpdateAlias", "DeleteAlias", "SetKeyPolicy", "CreateNetworkRule", "UpdateNetworkRule", "CreatePolicy", "UpdatePolicy",
    "CreateApplicationAccessPoint", "CreateClientKey", "ConnectKmsInstance",
    # R63-P3a: KMS instance/keystore/version/rotation changes. SetKeyPolicy and DisconnectKmsInstance are KMS 3.0 API
    # names NOT listed on the ActionTrail "audit events of KMS" page (checked 2026-10-21): kept, verify live.
    "UpdateKmsInstanceBindVpc", "UpdateKeyStore", "CreateKeyVersion", "UpdateRotationPolicy", "DisconnectKmsInstance",
    # RAM
    "CreateRole", "DeleteRole", "UpdateRole", "AttachPolicyToRole", "DetachPolicyFromRole", "CreatePolicyVersion", "SetDefaultPolicyVersion",
    "CreateUser", "CreateAccessKey", "UpdateAccessKey", "DeleteAccessKey", "CreateLoginProfile", "UpdateLoginProfile", "AttachPolicyToUser", "BindMFADevice", "UnbindMFADevice",
    # ECS role / metadata / network path
    "AttachInstanceRamRole", "DetachInstanceRamRole", "ModifyInstanceMetadataOptions", "RunInstances", "CreateInstance", "ResetDiskPassword", "ModifyInstanceAttribute",
    "AttachKeyPair", "InvokeCommand", "RunCommand", "SendFile", "StartTerminalSession",
    "UnassociateEipAddress", "AssociateEipAddress", "ReleaseEipAddress", "AuthorizeSecurityGroup", "ModifySecurityGroupRule",
    # trail / SLS / alerts
    "StopLogging", "DeleteTrail", "UpdateTrail", "DeleteLogStore", "UpdateLogStore", "DeleteProject", "UpdateAlert", "DeleteAlert", "DisableAlert",
  ]
}

# every KMS AsymmetricSign pages (the verifier also reconciles each against its own chain; an unmatched one = tamper)
resource "alicloud_log_alert" "kms_sign" {
  version           = "1.0"
  type              = "default"
  project_name      = alicloud_log_project.trail.project_name
  alert_name        = "mr-kms-sign"
  alert_displayname = "mr-verifier KMS AsymmetricSign"
  condition         = "n > 0"
  notify_threshold  = 1
  throttling        = "0s"
  query_list {
    logstore    = alicloud_log_store.trail.logstore_name
    chart_title = "sign"
    query       = "event.serviceName: Kms and event.eventName: AsymmetricSign | select count(1) as n"
    start       = "-6m"
    end         = "now"
  }
  schedule {
    type     = "FixedRate"
    interval = "5m"
  }
  notification_list {
    type        = "Webhook"
    service_uri = var.ntfy_webhook_url
    content     = "[aliyun] KMS AsymmetricSign x$${n} (mr-verifier key)"
  }
}
resource "alicloud_log_alert" "admin" {
  version           = "1.0"
  type              = "default"
  project_name      = alicloud_log_project.trail.project_name
  alert_name        = "mr-aliyun-admin"
  alert_displayname = "mr-verifier account admin change"
  condition         = "n > 0"
  notify_threshold  = 1
  throttling        = "0s"
  query_list {
    logstore    = alicloud_log_store.trail.logstore_name
    chart_title = "admin"
    query       = "event.eventName: (${join(" or ", local.admin_events)}) | select count(1) as n"
    start       = "-6m"
    end         = "now"
  }
  schedule {
    type     = "FixedRate"
    interval = "5m"
  }
  notification_list {
    type        = "Webhook"
    service_uri = var.ntfy_webhook_url
    content     = "[aliyun] admin / KMS / RAM / trail change x$${n}: check ActionTrail now"
  }
}
# heartbeat: fires daily on any trail traffic and pings Healthchecks (outside Alibaba; period 1 d, grace 2 h).
# If the trail, SLS or the alerting stops, Healthchecks pages the owner.
resource "alicloud_log_alert" "heartbeat" {
  version           = "1.0"
  type              = "default"
  project_name      = alicloud_log_project.trail.project_name
  alert_name        = "mr-aliyun-heartbeat"
  alert_displayname = "mr-verifier trail heartbeat"
  condition         = "n > 0" # R63-P3b: the alert only fires on trail traffic; a silent trail = missed ping
  notify_threshold  = 1
  throttling        = "0s"
  query_list {
    logstore    = alicloud_log_store.trail.logstore_name
    chart_title = "hb"
    query       = "* | select count(1) as n"
    start       = "-1d"
    end         = "now"
  }
  schedule {
    type     = "FixedRate"
    interval = "24h"
  }
  notification_list {
    type        = "Webhook"
    service_uri = var.healthchecks_url
    content     = "heartbeat $${n}"
  }
}

output "verifier_eip" { value = alicloud_eip_address.verifier.ip_address }
output "verifier_vpc" { value = alicloud_vpc.v.id }
output "kms_key_id" { value = var.kms_instance_id == "" ? "none (no KMS instance approved)" : alicloud_kms_key.cosign[0].id }
# KMS OpenAPI over the VPC endpoint (acs:SourceVpc is only present on VPC-endpoint requests; ActionTrail logs them)
output "kms_endpoint" { value = "kms-vpc.${var.region}.aliyuncs.com" }

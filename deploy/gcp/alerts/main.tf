# R48-P2-2: log-based alerts that page OUTSIDE Google (ntfy), replacing the old
# "AsymmetricSign beyond the audit chain count" metric. NOT APPLIED: the owner approves
# the project and costs first. Log-based alerts, one Pub/Sub channel and
# topic and one small function fit the free tiers at this volume.
#
#   terraform init && terraform plan -var project=... -var signer_internal_ip=...   (no apply without the owner)

terraform {
  required_providers { google = { source = "hashicorp/google", version = ">= 5.0" } }
}

variable "project" { type = string }
variable "region" {
  type    = string
  default = "us-east1"
}
variable "signer_sa" {
  type        = string
  description = "mr-signer@PROJECT.iam.gserviceaccount.com"
}
variable "signer_vm" {
  type    = string
  default = "mr-signer-1"
}
variable "network" {
  type    = string
  default = "mr-vpc"
}
variable "subnetwork" {
  type    = string
  default = "mr-subnet"
}
variable "signer_internal_ip" {
  type        = string
  description = "R49-P2-1: the reserved static internal IP of the signer VM (e.g. 10.10.0.5)"
}
# R49-P3: the ntfy topic URL is a capability. It lives only in Secret Manager (secret "mr-ntfy-url", created by
# hand with `gcloud secrets create ... --data-file=-` from the 0600 file); terraform never reads or stores it.
# Both alert paths therefore go through Pub/Sub and the forwarder, which reads the secret at runtime.

provider "google" { project = var.project }

locals {
  caller_network = "//compute.googleapis.com/projects/${var.project}/global/networks/${var.network}"
  kms            = "protoPayload.serviceName=\"cloudkms.googleapis.com\""
  # NB: in the Logging query language OR binds tighter than AND, so every mixed clause is parenthesised.
  # Each entry is one alert policy. Every AsymmetricSign pages (one page per release
  # signature is expected and cheap); the rest should never fire in normal operation.
  alerts = {
    every-asymmetric-sign = {
      sev    = "info"
      filter = "${local.kms} AND protoPayload.methodName=\"AsymmetricSign\""
    }
    sign-not-by-signer-vm = {
      sev = "critical"
      # R49-P2-1: not the attached SA, or not from the VM's RESERVED static internal IP on the pinned VPC
      # (Private Google Access calls carry callerIp = the VM's internal IP and callerNetwork = its VPC).
      # "gce-internal-ip" is NOT accepted: it is what any VM in any project shows.
      filter = "${local.kms} AND protoPayload.methodName=\"AsymmetricSign\" AND (protoPayload.authenticationInfo.principalEmail!=\"${var.signer_sa}\" OR protoPayload.requestMetadata.callerIp!=\"${google_compute_address.signer.address}\" OR protoPayload.requestMetadata.callerNetwork!=\"${local.caller_network}\")"
    }
    act-as-or-attach-sa = {
      sev    = "critical"
      filter = "(protoPayload.serviceName=\"iamcredentials.googleapis.com\" AND protoPayload.methodName=~\"GenerateAccessToken|GenerateIdToken|SignBlob|SignJwt\" AND NOT (protoPayload.resourceName=~\"^projects/-/serviceAccounts/mr-reconcile-reader@${var.project}\\\\.iam\\\\.gserviceaccount\\\\.com$\" AND protoPayload.authenticationInfo.principalSubject=~\"workloadIdentityPools/mr-verifier-aws/\" AND protoPayload.methodName=\"GenerateAccessToken\")) OR (protoPayload.authorizationInfo.permission=\"iam.serviceAccounts.actAs\" AND protoPayload.authorizationInfo.resourceAttributes.name=~\"${var.signer_sa}\") OR (protoPayload.serviceName=\"compute.googleapis.com\" AND protoPayload.methodName=~\"instances.(insert|setServiceAccount|setMetadata|setLabels)$\") OR (protoPayload.serviceName=\"iam.googleapis.com\" AND protoPayload.methodName=~\"CreateServiceAccountKey|UploadServiceAccountKey|SetIamPolicy\")"
    }
    key-version-lifecycle = {
      sev    = "critical"
      filter = "${local.kms} AND protoPayload.methodName=~\"DestroyCryptoKeyVersion|RestoreCryptoKeyVersion|UpdateCryptoKeyVersion|CreateCryptoKeyVersion|UpdateCryptoKeyPrimaryVersion|UpdateCryptoKey|ImportCryptoKeyVersion|SetIamPolicy\""
    }
    audit-config-and-iam = {
      sev    = "critical"
      filter = "protoPayload.methodName=~\"SetIamPolicy$\" OR protoPayload.serviceData.policyDelta.auditConfigDeltas:* OR protoPayload.metadata.datasetDeletion:* OR (protoPayload.serviceName=\"logging.googleapis.com\" AND protoPayload.methodName=~\"(Create|Update|Delete)(Sink|Exclusion|Bucket)|UpdateCmekSettings|UpdateSettings\") OR (protoPayload.serviceName=\"monitoring.googleapis.com\" AND protoPayload.methodName=~\"(Update|Delete)(AlertPolicy|NotificationChannel)\") OR ((protoPayload.serviceName=\"cloudfunctions.googleapis.com\" OR protoPayload.serviceName=\"run.googleapis.com\" OR protoPayload.serviceName=\"pubsub.googleapis.com\" OR protoPayload.serviceName=\"cloudscheduler.googleapis.com\") AND protoPayload.methodName=~\"Update|Delete|Replace|Pause\")"
    }
    iap-oslogin-admin = {
      sev    = "critical"
      filter = "(protoPayload.serviceName=\"iap.googleapis.com\" AND protoPayload.methodName=~\"SetIamPolicy|UpdateIapSettings|UpdateTunnelDestGroup|CreateTunnelDestGroup\") OR protoPayload.serviceData.policyDelta.bindingDeltas.role=~\"roles/(iap.tunnelResourceAccessor|compute.osAdminLogin|compute.osLogin|compute.instanceAdmin|iam.serviceAccountUser|iam.serviceAccountTokenCreator|owner|editor)\" OR (protoPayload.serviceName=\"oslogin.googleapis.com\" AND protoPayload.methodName=~\"ImportSshPublicKey|CreateSshPublicKey|UpdateSshPublicKey\")"
    }
  }
}

# 1) Make sure every sign and every credential mint is logged (DATA_READ is off by default).
resource "google_project_iam_audit_config" "kms" {
  project = var.project
  service = "cloudkms.googleapis.com"
  audit_log_config { log_type = "ADMIN_READ" }
  audit_log_config { log_type = "DATA_READ" }
  audit_log_config { log_type = "DATA_WRITE" }
}
resource "google_project_iam_audit_config" "iamcredentials" {
  project = var.project
  service = "iamcredentials.googleapis.com"
  audit_log_config { log_type = "DATA_READ" }
  audit_log_config { log_type = "DATA_WRITE" }
}

# R49-P2-1: the signer VM's reserved static internal IP (attach with --private-network-ip=<this> at create).
resource "google_compute_address" "signer" {
  name         = "mr-signer-internal"
  region       = var.region
  address_type = "INTERNAL"
  subnetwork   = var.subnetwork
  address      = var.signer_internal_ip
}

# 2) Path A: Cloud Monitoring alert policies → a Pub/Sub notification channel → forwarder → ntfy (outside Google).
resource "google_monitoring_notification_channel" "ntfy" {
  display_name = "mr-signer alerts (Pub/Sub → forwarder → ntfy)"
  type         = "pubsub"
  labels       = { topic = google_pubsub_topic.alerts.id }
}
resource "google_pubsub_topic_iam_member" "monitoring_pub" {
  topic  = google_pubsub_topic.alerts.id
  role   = "roles/pubsub.publisher"
  member = "serviceAccount:service-${data.google_project.this.number}@gcp-sa-monitoring-notification.iam.gserviceaccount.com"
}
data "google_project" "this" {}

resource "google_monitoring_alert_policy" "log_alert" {
  for_each     = local.alerts
  display_name = "mr-signer: ${each.key}"
  combiner     = "OR"
  severity     = upper(each.value.sev) == "INFO" ? "WARNING" : "CRITICAL"
  conditions {
    display_name = each.key
    condition_matched_log { filter = each.value.filter }
  }
  # Log-match alerts: page per event, minimum rate limit (5 min), auto-close after 30 min.
  alert_strategy {
    notification_rate_limit { period = "300s" }
    auto_close = "1800s"
  }
  notification_channels = [google_monitoring_notification_channel.ntfy.id]
  documentation {
    content   = "MandateRail signer GCP alert ${each.key}. See deploy/gcp/README.md §6."
    mime_type = "text/markdown"
  }
}

# 3) Path B (independent of Cloud Monitoring, no rate limit): a sink of the same
# events to Pub/Sub, and a ~40-line forwarder that POSTs each one to ntfy.
resource "google_pubsub_topic" "alerts" { name = "mr-signer-alerts" }

resource "google_logging_project_sink" "alerts" {
  name                   = "mr-signer-alerts"
  destination            = "pubsub.googleapis.com/${google_pubsub_topic.alerts.id}"
  filter                 = join(" OR ", [for k, a in local.alerts : "(${a.filter})"])
  unique_writer_identity = true
}

resource "google_pubsub_topic_iam_member" "sink_pub" {
  topic  = google_pubsub_topic.alerts.id
  role   = "roles/pubsub.publisher"
  member = google_logging_project_sink.alerts.writer_identity
}

# The forwarder runs as its own SA with no roles beyond receiving the push.
# Deploy (not applied):
#   gcloud functions deploy mr-alert-forwarder --gen2 --runtime=nodejs20 --region=$REGION \
#     --source=deploy/gcp/alerts/forwarder --entry-point=forward --trigger-topic=mr-signer-alerts \
#     --service-account=mr-alert-fwd@$PROJECT.iam.gserviceaccount.com \
#     --set-secrets=NTFY_URL=mr-ntfy-url:latest --max-instances=2
# R49-P2-2 dead-man (outside Google): Cloud Scheduler publishes a daily heartbeat; the forwarder posts it to
# ntfy (tag "heartbeat") AND pings Healthchecks (secret mr-hc-fwd-url, period 1 day, grace 2 h). The verifier
# polls the topic and pages if the newest heartbeat is older than 26 h (packages/signer/src/verifier/reconcile.ts);
# Healthchecks pages the owner by email independently.
#   --set-secrets=NTFY_URL=mr-ntfy-url:latest,HC_URL=mr-hc-fwd-url:latest
resource "google_cloud_scheduler_job" "heartbeat" {
  name     = "mr-alert-heartbeat"
  region   = var.region
  schedule = "0 12 * * *"
  pubsub_target {
    topic_name = google_pubsub_topic.alerts.id
    data       = base64encode("{\"heartbeat\":true}")
  }
}

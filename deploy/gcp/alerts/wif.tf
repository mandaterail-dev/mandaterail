# R50-P2: Workload Identity Federation so the verifier (AWS account, instance role mr-verifier) can READ the
# Cloud KMS audit log for reconciliation. No GCP key file. NOT APPLIED.

variable "verifier_aws_account" {
  type        = string
  description = "the verifier's 12-digit AWS account id"
}
variable "verifier_aws_role" {
  type    = string
  default = "mr-verifier"
}

resource "google_iam_workload_identity_pool" "verifier" {
  workload_identity_pool_id = "mr-verifier-aws"
  display_name              = "mr-verifier (AWS)"
}

resource "google_iam_workload_identity_pool_provider" "aws" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.verifier.workload_identity_pool_id
  workload_identity_pool_provider_id = "aws-verifier"
  aws { account_id = var.verifier_aws_account }
  # only the verifier instance role's sessions (assumed-role/mr-verifier/i-...), nothing else in that account
  attribute_mapping = {
    "google.subject"     = "assertion.arn"
    "attribute.aws_role" = "assertion.arn.contains('assumed-role') ? assertion.arn.extract('{account_arn}assumed-role/') + 'assumed-role/' + assertion.arn.extract('assumed-role/{role_name}/') : assertion.arn"
  }
  attribute_condition = "assertion.arn.startsWith('arn:aws:sts::${var.verifier_aws_account}:assumed-role/${var.verifier_aws_role}/i-')"
}

resource "google_service_account" "reader" {
  account_id   = "mr-reconcile-reader"
  display_name = "mr-verifier reconcile reader (logs only)"
}

# read access to Data Access audit logs, nothing else
resource "google_project_iam_member" "reader_logs" {
  project = var.project
  role    = "roles/logging.privateLogViewer"
  member  = "serviceAccount:${google_service_account.reader.email}"
}

# only the federated verifier role may impersonate the reader. R51-P3: workloadIdentityUser alone is enough for the
# federated token to call generateAccessToken; serviceAccountTokenCreator (SignBlob/SignJwt/id tokens) is NOT granted.
resource "google_service_account_iam_member" "reader_wif" {
  service_account_id = google_service_account.reader.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.verifier.name}/attribute.aws_role/arn:aws:sts::${var.verifier_aws_account}:assumed-role/${var.verifier_aws_role}"
}

output "wif_provider" { value = google_iam_workload_identity_pool_provider.aws.name }
output "reader_sa" { value = google_service_account.reader.email }

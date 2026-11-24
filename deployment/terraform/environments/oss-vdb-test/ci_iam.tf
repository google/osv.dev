# Cross-project CI/CD and API E2E test runner IAM bindings in oss-vdb-test

variable "terraform_plan_service_account_email" {
  type        = string
  description = "Read-only Terraform plan service account email."
  default     = "terraform-plan@oss-vdb.iam.gserviceaccount.com"
}

variable "api_e2e_tester_service_account_email" {
  type        = string
  description = "API E2E snapshot test runner service account email."
  default     = "api-e2e-tester@oss-vdb.iam.gserviceaccount.com"
}

resource "google_project_iam_member" "terraform_plan_roles" {
  for_each = var.terraform_plan_service_account_email != "" ? toset([
    "roles/viewer",
    "roles/iam.securityReviewer",
    "roles/compute.networkViewer",
  ]) : toset([])

  project = "oss-vdb-test"
  role    = each.value
  member  = "serviceAccount:${var.terraform_plan_service_account_email}"
}

resource "google_project_iam_member" "api_e2e_tester_datastore_viewer" {
  count   = var.api_e2e_tester_service_account_email != "" ? 1 : 0
  project = "oss-vdb-test"
  role    = "roles/datastore.viewer"
  member  = "serviceAccount:${var.api_e2e_tester_service_account_email}"

  condition {
    title       = "Database Isolation"
    description = "Restricts this service account to only access the created Datastore database."
    expression  = "resource.name == '${module.osv_pipeline.datastore_database_id}'"
  }
}

resource "google_project_iam_member" "api_e2e_tester_service_controller" {
  count   = var.api_e2e_tester_service_account_email != "" ? 1 : 0
  project = "oss-vdb-test"
  role    = "roles/servicemanagement.serviceController"
  member  = "serviceAccount:${var.api_e2e_tester_service_account_email}"
}

resource "google_storage_bucket_iam_member" "api_e2e_tester_vulnerabilities_viewer" {
  count  = var.api_e2e_tester_service_account_email != "" ? 1 : 0
  bucket = module.osv_pipeline.vulnerabilities_export_bucket_name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${var.api_e2e_tester_service_account_email}"
}

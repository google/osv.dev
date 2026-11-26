# OSV-specific GKE Workload Identity service accounts and bucket bindings.
# Opt-in via var.enable_workload_identity (keeps count/for_each statically known even when
# var.workload_identity_pool or var.backup_service_account_email depend on newly created resources).

resource "google_service_account" "vulnfeeds_sa" {
  count        = var.enable_workload_identity ? 1 : 0
  project      = var.project_id
  account_id   = "osv-vulnfeeds"
  display_name = "OSV Vulnfeeds Workload Identity SA"
  description  = "Dedicated Workload Identity SA for external vulnfeeds converter and mirror CronJobs (feed conversion buckets and tracing only)."
}

resource "google_service_account_iam_member" "vulnfeeds_workload_identity_user" {
  count              = var.enable_workload_identity ? 1 : 0
  service_account_id = google_service_account.vulnfeeds_sa[0].name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.workload_identity_pool}[default/osv-vulnfeeds]"

  lifecycle {
    precondition {
      condition     = var.workload_identity_pool != ""
      error_message = "workload_identity_pool must be non-empty when enable_workload_identity is true."
    }
  }
}

resource "google_storage_bucket_iam_member" "vulnfeeds_cve_osv_conversion" {
  count  = var.enable_workload_identity ? 1 : 0
  bucket = google_storage_bucket.cve_osv_conversion.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.vulnfeeds_sa[0].email}"
}

resource "google_storage_bucket_iam_member" "vulnfeeds_debian_osv_conversion" {
  count  = var.enable_workload_identity ? 1 : 0
  bucket = google_storage_bucket.debian_osv_conversion_bucket.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.vulnfeeds_sa[0].email}"
}

resource "google_project_iam_member" "vulnfeeds_trace_roles" {
  for_each = var.enable_workload_identity ? toset([
    "roles/cloudtrace.agent",
    "roles/telemetry.tracesWriter",
  ]) : toset([])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.vulnfeeds_sa[0].email}"
}

resource "google_storage_bucket_iam_member" "backup_backups_bucket" {
  count  = var.enable_workload_identity ? 1 : 0
  bucket = google_storage_bucket.backups_bucket.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${var.backup_service_account_email}"

  lifecycle {
    precondition {
      condition     = var.backup_service_account_email != ""
      error_message = "backup_service_account_email must be non-empty when enable_workload_identity is true."
    }
  }
}

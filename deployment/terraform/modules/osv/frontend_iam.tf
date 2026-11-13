# Dedicated read-only Cloud Run serving service account (osv-website, osv-grpc-v1, osv-grpc-backend*)

resource "google_service_account" "frontend_sa" {
  project      = var.project_id
  account_id   = "osv-frontend"
  display_name = "OSV Cloud Run Frontend Service Account"
}

resource "google_project_iam_member" "frontend_datastore_viewer" {
  project = var.project_id
  role    = "roles/datastore.viewer"
  member  = "serviceAccount:${google_service_account.frontend_sa.email}"

  condition {
    title       = "Database Isolation"
    description = "Restricts this service account to only access the created Datastore database."
    expression  = "resource.name == '${var.datastore_database_id}'"
  }
}

resource "google_project_iam_member" "frontend_project_roles" {
  for_each = toset([
    "roles/servicemanagement.serviceController",
    "roles/cloudtrace.agent",
    "roles/telemetry.tracesWriter",
  ])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.frontend_sa.email}"
}

resource "google_storage_bucket_iam_member" "frontend_vulnerabilities_viewer" {
  bucket = var.vulnerabilities_export_bucket
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.frontend_sa.email}"
}

resource "google_storage_bucket_iam_member" "frontend_public_import_logs_viewer" {
  bucket = google_storage_bucket.osv_public_import_logs.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.frontend_sa.email}"
}

resource "google_storage_bucket_iam_member" "frontend_cve_osv_conversion_viewer" {
  bucket = google_storage_bucket.cve_osv_conversion.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.frontend_sa.email}"
}

resource "google_pubsub_topic_iam_member" "frontend_failed_tasks_publisher" {
  project = var.project_id
  topic   = var.failed_tasks_topic_name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_service_account.frontend_sa.email}"
}

resource "google_service_account_iam_member" "frontend_deployer_act_as" {
  for_each = toset([
    "serviceAccount:deployment@oss-vdb.iam.gserviceaccount.com",
    "serviceAccount:terraform-apply@oss-vdb.iam.gserviceaccount.com",
  ])

  service_account_id = google_service_account.frontend_sa.name
  role               = "roles/iam.serviceAccountUser"
  member             = each.value
}

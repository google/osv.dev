# GKE Worker Service Account and secure least-privilege IAM permissions

# Dedicated GKE Worker Service Account
resource "google_service_account" "worker_sa" {
  project      = var.project_id
  account_id   = var.worker_service_account_id
  display_name = "OSV GKE Worker Service Account"
}

# Datastore roles with database-specific IAM conditions for multi-tenant isolation
resource "google_project_iam_member" "worker_datastore_roles" {
  for_each = toset([
    "roles/datastore.user",
    "roles/datastore.importExportAdmin"
  ])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.worker_sa.email}"

  condition {
    title       = "Database Isolation"
    description = "Restricts this service account to only access the created Datastore database."
    expression  = "resource.name == '${google_firestore_database.datastore.id}'"
  }
}

# Cloud Monitoring roles at the project level
resource "google_project_iam_member" "worker_monitoring_roles" {
  for_each = toset([
    "roles/monitoring.metricWriter",
    "roles/monitoring.viewer"
  ])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.worker_sa.email}"
}

# Bucket-level GCS access to secure vulnerability exports and backups
resource "google_storage_bucket_iam_member" "worker_export_bucket" {
  bucket = google_storage_bucket.osv_vulnerabilities_export.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.worker_sa.email}"
}

resource "google_storage_bucket_iam_member" "worker_backup_bucket" {
  bucket = google_storage_bucket.affected_commits_backups_bucket.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.worker_sa.email}"
}

# Subscription-level Pub/Sub access to prevent queue cross-talk/task-stealing
resource "google_pubsub_subscription_iam_member" "worker_subscriber" {
  project      = var.project_id
  subscription = google_pubsub_subscription.default_work.name
  role         = "roles/pubsub.subscriber"
  member       = "serviceAccount:${google_service_account.worker_sa.email}"
}

resource "google_pubsub_subscription_iam_member" "worker_extra_subscribers" {
  for_each     = toset(var.extra_work_pools)
  project      = var.project_id
  subscription = google_pubsub_subscription.work_pools[each.value].name
  role         = "roles/pubsub.subscriber"
  member       = "serviceAccount:${google_service_account.worker_sa.email}"
}

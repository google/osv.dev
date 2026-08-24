# IAM permissions for the GKE worker service account to access OSV-specific buckets and topics

resource "google_storage_bucket_iam_member" "worker_cve_osv_conversion" {
  count  = var.worker_service_account_email != "" ? 1 : 0
  bucket = google_storage_bucket.cve_osv_conversion.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${var.worker_service_account_email}"
}

resource "google_storage_bucket_iam_member" "worker_debian_osv_conversion" {
  count  = var.worker_service_account_email != "" ? 1 : 0
  bucket = google_storage_bucket.debian_osv_conversion_bucket.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${var.worker_service_account_email}"
}

resource "google_storage_bucket_iam_member" "worker_public_import_logs" {
  count  = var.worker_service_account_email != "" ? 1 : 0
  bucket = google_storage_bucket.osv_public_import_logs.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${var.worker_service_account_email}"
}

resource "google_storage_bucket_iam_member" "worker_backups" {
  count  = var.worker_service_account_email != "" ? 1 : 0
  bucket = google_storage_bucket.backups_bucket.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${var.worker_service_account_email}"
}

resource "google_storage_bucket_iam_member" "worker_sitemap" {
  count  = var.worker_service_account_email != "" ? 1 : 0
  bucket = google_storage_bucket.osv_dev_sitemap_bucket.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${var.worker_service_account_email}"
}

resource "google_pubsub_topic_iam_member" "worker_pypi_bridge_publisher" {
  count   = var.worker_service_account_email != "" ? 1 : 0
  project = var.project_id
  topic   = google_pubsub_topic.pypi_bridge.name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${var.worker_service_account_email}"
}

resource "google_storage_bucket_iam_member" "worker_indexer_configs" {
  count  = var.worker_service_account_email != "" && var.indexer_configs_bucket != "" ? 1 : 0
  bucket = var.indexer_configs_bucket
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${var.worker_service_account_email}"
}

resource "google_storage_bucket_iam_member" "worker_indexer_repos" {
  count  = var.worker_service_account_email != "" && var.indexer_repos_bucket != "" ? 1 : 0
  bucket = var.indexer_repos_bucket
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${var.worker_service_account_email}"
}

resource "google_pubsub_topic_iam_member" "worker_indexer_work_publisher" {
  count   = var.worker_service_account_email != "" && var.indexer_topic != "" ? 1 : 0
  project = var.project_id
  topic   = var.indexer_topic
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${var.worker_service_account_email}"
}

resource "google_pubsub_subscription_iam_member" "worker_indexer_work_subscriber" {
  count        = var.worker_service_account_email != "" && var.indexer_subscription != "" ? 1 : 0
  project      = var.project_id
  subscription = var.indexer_subscription
  role         = "roles/pubsub.subscriber"
  member       = "serviceAccount:${var.worker_service_account_email}"
}

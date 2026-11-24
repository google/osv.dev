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

# GKE Node Service Account and Monitoring roles at the project level
resource "google_project_iam_member" "worker_node_roles" {
  for_each = toset([
    "roles/container.defaultNodeServiceAccount",
    "roles/monitoring.metricWriter",
    "roles/monitoring.viewer",
    "roles/cloudtrace.agent",
    "roles/telemetry.tracesWriter",
    "roles/artifactregistry.reader"
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

resource "google_storage_bucket_iam_member" "public_export_bucket" {
  for_each = var.public_export_bucket ? toset([
    "roles/storage.objectViewer",
    "roles/storage.legacyBucketReader",
  ]) : toset([])

  bucket = google_storage_bucket.osv_vulnerabilities_export.name
  role   = each.value
  member = "allUsers"
}

resource "google_storage_bucket_iam_member" "worker_backup_bucket" {
  bucket = google_storage_bucket.affected_commits_backups_bucket.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.worker_sa.email}"
}

# Topic-level Pub/Sub publisher access for task creation and retry
resource "google_pubsub_topic_iam_member" "worker_tasks_publisher" {
  project = var.project_id
  topic   = google_pubsub_topic.tasks.name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_service_account.worker_sa.email}"
}

resource "google_pubsub_topic_iam_member" "worker_failed_tasks_publisher" {
  project = var.project_id
  topic   = google_pubsub_topic.failed_tasks.name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_service_account.worker_sa.email}"
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

resource "google_pubsub_subscription_iam_member" "worker_recovery_subscriber" {
  project      = var.project_id
  subscription = google_pubsub_subscription.recovery.name
  role         = "roles/pubsub.subscriber"
  member       = "serviceAccount:${google_service_account.worker_sa.email}"
}

# Cloud SQL and Secret Manager permissions for the GKE worker service account
resource "google_project_iam_member" "worker_cloudsql_client" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.worker_sa.email}"
}

resource "google_secret_manager_secret_iam_member" "worker_postgres_secret_access" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.postgres_worker_password.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.worker_sa.email}"
}

# Cloud SQL IAM authentication permissions for the Cloud Build deployment service account
# (retained alongside google_sql_user.deployment for backwards compatibility until removed).
resource "google_project_iam_member" "deployment_cloudsql_roles" {
  for_each = var.deployment_service_account_email != "" ? toset([
    "roles/cloudsql.client",
    "roles/cloudsql.instanceUser",
  ]) : toset([])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${var.deployment_service_account_email}"
}

# Dedicated service account for the osv-db-migrate Cloud Run Job (runs goose schema migrations over Private IP)
resource "google_service_account" "migrator_sa" {
  project      = var.project_id
  account_id   = var.migrator_service_account_id
  display_name = "OSV Database Migrations Service Account"
}

resource "google_project_iam_member" "migrator_cloudsql_roles" {
  for_each = toset([
    "roles/cloudsql.client",
    "roles/cloudsql.instanceUser",
  ])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.migrator_sa.email}"
}

resource "google_service_account_iam_member" "migrator_deployer_act_as" {
  for_each = toset([
    for email in var.migrator_deployer_service_account_emails : "serviceAccount:${email}"
  ])

  service_account_id = google_service_account.migrator_sa.name
  role               = "roles/iam.serviceAccountUser"
  member             = each.value
}

# Allow Cloud Build's deployment SA to update and execute only the osv-db-migrate Cloud Run Job.
resource "google_cloud_run_v2_job_iam_member" "deployment_goose_migrate_developer" {
  count    = var.deployment_service_account_email != "" ? 1 : 0
  project  = var.project_id
  location = google_cloud_run_v2_job.goose_migrate.location
  name     = google_cloud_run_v2_job.goose_migrate.name
  role     = "roles/run.developer"
  member   = "serviceAccount:${var.deployment_service_account_email}"
}

# GKE cluster-scoped RBAC and Cloud Deploy execution permissions for gke-workers,
# plus project-level roles/run.viewer so CI/CD can poll Cloud Run operation status
# (`run.operations.get`) during `gcloud run jobs update`/`execute --wait` in private-osv
# (overlaps with roles/run.admin in modules/osv on oss-vdb/oss-vdb-test).
resource "google_project_iam_member" "deployment_clouddeploy_roles" {
  for_each = var.deployment_service_account_email != "" ? toset([
    "roles/container.admin",
    "roles/clouddeploy.jobRunner",
    "roles/logging.logWriter",
    "roles/run.viewer",
  ]) : toset([])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${var.deployment_service_account_email}"
}


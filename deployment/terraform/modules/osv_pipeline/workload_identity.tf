# GKE Workload Identity service accounts for isolating high-risk workloads on the workers cluster.
# Opt-in via var.enable_workload_identity (Phase 1: additive GSAs + cluster pool; Phase 2: var.enable_gke_metadata).

resource "google_service_account" "gitter_sa" {
  count        = var.enable_workload_identity ? 1 : 0
  project      = var.project_id
  account_id   = "osv-gitter"
  display_name = "OSV Gitter Workload Identity SA"
  description  = "Zero-data-permission Workload Identity SA for the gitter Git caching service (tracing only)."
}

resource "google_service_account" "backup_sa" {
  count        = var.enable_workload_identity ? 1 : 0
  project      = var.project_id
  account_id   = "osv-backup"
  display_name = "OSV Backup Workload Identity SA"
  description  = "Dedicated Workload Identity SA for the Datastore backup CronJob (datastore.importExportAdmin and backup buckets only)."
}

resource "google_service_account" "monitoring_sa" {
  count        = var.enable_workload_identity ? 1 : 0
  project      = var.project_id
  account_id   = "osv-monitoring"
  display_name = "OSV Monitoring Workload Identity SA"
  description  = "Read-only Workload Identity SA for Grafana GMP frontend and custom-metrics-stackdriver-adapter (monitoring.viewer only)."
}

locals {
  workload_identity_pool = var.enable_workload_identity ? "${var.project_id}.svc.id.goog" : ""

  pipeline_workload_identity_bindings = var.enable_workload_identity ? {
    worker = {
      sa_name = google_service_account.worker_sa.name
      ksa     = "default/osv-worker"
    }
    indexer = {
      sa_name = google_service_account.worker_sa.name
      ksa     = "default/osv-indexer"
    }
    gitter = {
      sa_name = google_service_account.gitter_sa[0].name
      ksa     = "default/osv-gitter"
    }
    backup = {
      sa_name = google_service_account.backup_sa[0].name
      ksa     = "default/osv-backup"
    }
    monitoring = {
      sa_name = google_service_account.monitoring_sa[0].name
      ksa     = "default/osv-monitoring"
    }
    metrics_adapter = {
      sa_name = google_service_account.monitoring_sa[0].name
      ksa     = "custom-metrics/custom-metrics-stackdriver-adapter"
    }
  } : {}
}

resource "google_service_account_iam_member" "pipeline_workload_identity_user" {
  for_each = local.pipeline_workload_identity_bindings

  service_account_id = each.value.sa_name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${local.workload_identity_pool}[${each.value.ksa}]"

  depends_on = [google_container_cluster.workers]
}

# --- osv-gitter (zero data permissions; OTLP tracing only) ---

resource "google_project_iam_member" "gitter_trace_roles" {
  for_each = var.enable_workload_identity ? toset([
    "roles/cloudtrace.agent",
    "roles/telemetry.tracesWriter",
  ]) : toset([])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.gitter_sa[0].email}"
}

# --- osv-backup (Datastore export + AffectedCommits backup bucket + Cloud Logging) ---

resource "google_project_iam_member" "backup_datastore_export" {
  count   = var.enable_workload_identity ? 1 : 0
  project = var.project_id
  role    = "roles/datastore.importExportAdmin"
  member  = "serviceAccount:${google_service_account.backup_sa[0].email}"

  condition {
    title       = "Database Isolation"
    description = "Restricts this service account to only access the created Datastore database."
    expression  = "resource.name == '${google_firestore_database.datastore.id}'"
  }
}

resource "google_project_iam_member" "backup_log_writer" {
  count   = var.enable_workload_identity ? 1 : 0
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.backup_sa[0].email}"
}

resource "google_storage_bucket_iam_member" "backup_affected_commits_bucket" {
  count  = var.enable_workload_identity ? 1 : 0
  bucket = google_storage_bucket.affected_commits_backups_bucket.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.backup_sa[0].email}"
}

# --- osv-monitoring (read-only Cloud Monitoring / GMP queries) ---

resource "google_project_iam_member" "monitoring_viewer" {
  count   = var.enable_workload_identity ? 1 : 0
  project = var.project_id
  role    = "roles/monitoring.viewer"
  member  = "serviceAccount:${google_service_account.monitoring_sa[0].email}"
}

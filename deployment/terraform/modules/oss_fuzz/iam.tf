# Dedicated least-privilege GKE node and Workload Identity service accounts for oss-fuzz-workers.

# ---------------------------------------------------------------------------
# GKE Node Service Account (zero application/data permissions)
# ---------------------------------------------------------------------------

resource "google_service_account" "node_sa" {
  project      = var.project_id
  account_id   = "oss-fuzz-node"
  display_name = "OSS-Fuzz GKE Node Service Account"
}

resource "google_project_iam_member" "node_roles" {
  for_each = toset([
    "roles/container.defaultNodeServiceAccount",
    "roles/monitoring.metricWriter",
    "roles/artifactregistry.reader",
  ])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.node_sa.email}"
}

resource "google_service_account_iam_member" "node_deployer_act_as" {
  for_each = toset([
    "serviceAccount:deployment@oss-vdb.iam.gserviceaccount.com",
    "serviceAccount:terraform-apply@oss-vdb.iam.gserviceaccount.com",
  ])

  service_account_id = google_service_account.node_sa.name
  role               = "roles/iam.serviceAccountUser"
  member             = each.value
}

# ---------------------------------------------------------------------------
# Workload Identity Service Accounts (1 per workload on oss-fuzz-workers)
# ---------------------------------------------------------------------------

resource "google_service_account" "worker_sa" {
  project      = var.project_id
  account_id   = "oss-fuzz-worker"
  display_name = "OSS-Fuzz Worker Workload Identity SA"
}

resource "google_service_account" "importer_sa" {
  project      = var.project_id
  account_id   = "oss-fuzz-importer"
  display_name = "OSS-Fuzz Importer Workload Identity SA"
}

# make-bugs-public binds to the default Compute Engine SA for Issue Tracker access.
data "google_compute_default_service_account" "default" {
  project = var.project_id
}

resource "google_service_account" "process_results_sa" {
  project      = var.project_id
  account_id   = "oss-fuzz-process-results"
  display_name = "OSS-Fuzz Process Results Workload Identity SA"
}

resource "google_service_account" "metrics_adapter_sa" {
  project      = var.project_id
  account_id   = "oss-fuzz-metrics-adapter"
  display_name = "OSS-Fuzz Stackdriver Metrics Adapter Workload Identity SA"
}

locals {
  datastore_workloads = {
    worker           = google_service_account.worker_sa.email
    importer         = google_service_account.importer_sa.email
    make_bugs_public = data.google_compute_default_service_account.default.email
    process_results  = google_service_account.process_results_sa.email
  }

  workload_identity_bindings = {
    worker = {
      sa_name = google_service_account.worker_sa.name
      ksa     = "default/oss-fuzz-worker"
    }
    importer = {
      sa_name = google_service_account.importer_sa.name
      ksa     = "default/oss-fuzz-importer"
    }
    make_bugs_public = {
      sa_name = data.google_compute_default_service_account.default.name
      ksa     = "default/oss-fuzz-make-bugs-public"
    }
    process_results = {
      sa_name = google_service_account.process_results_sa.name
      ksa     = "default/oss-fuzz-process-results"
    }
    metrics_adapter = {
      sa_name = google_service_account.metrics_adapter_sa.name
      ksa     = "custom-metrics/custom-metrics-stackdriver-adapter"
    }
  }
}

# Bind each K8s ServiceAccount to its dedicated GCP ServiceAccount.
resource "google_service_account_iam_member" "workload_identity_user" {
  for_each = local.workload_identity_bindings

  service_account_id = each.value.sa_name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${google_container_cluster.workers.workload_identity_config[0].workload_pool}[${each.value.ksa}]"

  depends_on = [google_container_cluster.workers]
}

# Shared Datastore access scoped to the (default) database for the dedicated Python workload GSAs.
resource "google_project_iam_member" "workload_datastore_user" {
  for_each = local.datastore_workloads

  project = var.project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${each.value}"

  condition {
    title       = "Database Isolation"
    description = "Restricts this service account to only access the created Datastore database."
    expression  = "resource.name == '${var.datastore_database_id}'"
  }
}

# Cloud Logging write access for the dedicated Python workload GSAs (osv.logs.setup_gcp_logging).
resource "google_project_iam_member" "workload_log_writer" {
  for_each = local.datastore_workloads

  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${each.value}"
}

# --- oss-fuzz-worker ---

resource "google_pubsub_subscription_iam_member" "worker_oss_fuzz_tasks_subscriber" {
  project      = var.project_id
  subscription = google_pubsub_subscription.oss_fuzz_tasks.name
  role         = "roles/pubsub.subscriber"
  member       = "serviceAccount:${google_service_account.worker_sa.email}"
}

# --- oss-fuzz-importer ---

resource "google_pubsub_topic_iam_member" "importer_tasks_publisher" {
  project = var.project_id
  topic   = var.tasks_topic_name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_service_account.importer_sa.email}"
}

resource "google_storage_bucket_iam_member" "importer_public_import_logs_object_user" {
  bucket = var.public_import_logs_bucket
  role   = "roles/storage.objectUser"
  member = "serviceAccount:${google_service_account.importer_sa.email}"
}

resource "google_storage_bucket_iam_member" "importer_oss_fuzz_export_object_user" {
  bucket = var.oss_fuzz_export_bucket
  role   = "roles/storage.objectUser"
  member = "serviceAccount:${google_service_account.importer_sa.email}"
}

# --- oss-fuzz-process-results ---

resource "google_pubsub_topic_iam_member" "process_results_tasks_publisher" {
  project = var.project_id
  topic   = var.tasks_topic_name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_service_account.process_results_sa.email}"
}

# --- oss-fuzz-metrics-adapter ---

resource "google_project_iam_member" "metrics_adapter_monitoring_viewer" {
  project = var.project_id
  role    = "roles/monitoring.viewer"
  member  = "serviceAccount:${google_service_account.metrics_adapter_sa.email}"
}

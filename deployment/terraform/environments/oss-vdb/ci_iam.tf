# CI/CD, testing, and auxiliary service accounts in oss-vdb, plus public Artifact Registry read access

# ---------------------------------------------------------------------------
# Service Accounts (imported from existing GCP resources)
# ---------------------------------------------------------------------------

resource "google_service_account" "terraform_plan" {
  project      = "oss-vdb"
  account_id   = "terraform-plan"
  display_name = "terraform-plan"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_service_account" "api_e2e_tester" {
  project      = "oss-vdb"
  account_id   = "api-e2e-tester"
  display_name = "api-e2e-tester"
  description  = "Service account to allow oss-vdb to access oss-vdb-test database"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_service_account" "pr_ci_runner" {
  project      = "oss-vdb"
  account_id   = "pr-ci-runner"
  display_name = "PR CI Runner"
  description  = "Minimal service account for untrusted GitHub PR Cloud Build unit tests"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_service_account" "cloud_build_trigger_scheduler" {
  project      = "oss-vdb"
  account_id   = "cloud-build-trigger-scheduler"
  display_name = "Cloud Build Trigger Scheduler"
  description  = "Service account for running Cloud Build triggers in a Cloud Scheduler job"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_service_account" "pypi_publisher" {
  project      = "oss-vdb"
  account_id   = "pypi-publisher"
  display_name = "PyPI Vulnerability Publisher"
  description  = "Dedicated runtime service account for the pypi Cloud Function (publishes advisories to PyPI via pypi-bridge Pub/Sub topic)."

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_service_account" "pypa_triage" {
  project      = "oss-vdb"
  account_id   = "pypa-triage"
  display_name = "PyPA Triage Cloud Build Runner"
  description  = "Dedicated Cloud Build service account for the scheduled pypa-triage job (BigQuery PyPI metadata export to gs://pypa-advisory-db)."

  lifecycle {
    prevent_destroy = true
  }
}

import {
  to = google_service_account.terraform_plan
  id = "projects/oss-vdb/serviceAccounts/terraform-plan@oss-vdb.iam.gserviceaccount.com"
}

import {
  to = google_service_account.api_e2e_tester
  id = "projects/oss-vdb/serviceAccounts/api-e2e-tester@oss-vdb.iam.gserviceaccount.com"
}

import {
  to = google_service_account.pr_ci_runner
  id = "projects/oss-vdb/serviceAccounts/pr-ci-runner@oss-vdb.iam.gserviceaccount.com"
}

import {
  to = google_service_account.cloud_build_trigger_scheduler
  id = "projects/oss-vdb/serviceAccounts/cloud-build-trigger-scheduler@oss-vdb.iam.gserviceaccount.com"
}

import {
  to = google_service_account.pypi_publisher
  id = "projects/oss-vdb/serviceAccounts/pypi-publisher@oss-vdb.iam.gserviceaccount.com"
}

import {
  to = google_service_account.pypa_triage
  id = "projects/oss-vdb/serviceAccounts/pypa-triage@oss-vdb.iam.gserviceaccount.com"
}

# ---------------------------------------------------------------------------
# Project-Level IAM Bindings in oss-vdb
# ---------------------------------------------------------------------------

# Least-privilege control-plane read-only role for PR terraform-plan builds.
# When adding a new GCP resource type to Terraform, add its .get / .getIamPolicy
# permission here AND update the matching role in oss-vdb-test (see deployment/README.md).
resource "google_project_iam_custom_role" "terraform_plan_reader" {
  project     = "oss-vdb"
  role_id     = "terraformPlanReader"
  title       = "Terraform Plan Reader"
  description = "Least-privilege control-plane read-only role for terraform-plan@oss-vdb (metadata and IAM policy reads only; zero data-plane or export permissions)."
  permissions = [
    "artifactregistry.repositories.get",
    "artifactregistry.repositories.getIamPolicy",
    "certificatemanager.certmapentries.get",
    "certificatemanager.certmaps.get",
    "certificatemanager.certs.get",
    "certificatemanager.dnsauthorizations.get",
    "cloudsql.databases.get",
    "cloudsql.instances.get",
    "cloudsql.users.get",
    "cloudsql.users.list",
    "compute.backendBuckets.get",
    "compute.backendServices.get",
    "compute.disks.get",
    "compute.globalAddresses.get",
    "compute.globalForwardingRules.get",
    "compute.instanceGroupManagers.get",
    "compute.instanceGroupManagers.list",
    "compute.networks.get",
    "compute.projects.get",
    "compute.regionNetworkEndpointGroups.get",
    "compute.regions.get",
    "compute.reservationBlocks.list",
    "compute.reservations.get",
    "compute.routers.get",
    "compute.subnetworks.get",
    "compute.targetHttpProxies.get",
    "compute.targetHttpsProxies.get",
    "compute.urlMaps.get",
    "compute.zones.get",
    "container.clusters.get",
    "datastore.databases.get",
    "datastore.databases.getMetadata",
    "iam.roles.get",
    "iam.serviceAccounts.get",
    "iam.serviceAccounts.getIamPolicy",
    "monitoring.alertPolicies.get",
    "pubsub.subscriptions.get",
    "pubsub.subscriptions.getIamPolicy",
    "pubsub.topics.get",
    "pubsub.topics.getIamPolicy",
    "redis.instances.get",
    "resourcemanager.projects.get",
    "resourcemanager.projects.getIamPolicy",
    "run.configurations.get",
    "run.domainmappings.get",
    "run.locations.list",
    "run.revisions.get",
    "run.routes.get",
    "run.services.get",
    "run.services.getIamPolicy",
    "secretmanager.secrets.get",
    "secretmanager.secrets.getIamPolicy",
    "servicemanagement.services.get",
    "servicenetworking.services.get",
    "serviceusage.services.get",
    "serviceusage.services.list",
    "storage.buckets.get",
    "storage.buckets.getIamPolicy",
    "vpcaccess.connectors.get",
  ]
}

import {
  to = google_project_iam_custom_role.terraform_plan_reader
  id = "projects/oss-vdb/roles/terraformPlanReader"
}

resource "google_project_iam_member" "terraform_plan_reader" {
  project = "oss-vdb"
  role    = google_project_iam_custom_role.terraform_plan_reader.name
  member  = "serviceAccount:${google_service_account.terraform_plan.email}"
}

resource "google_project_iam_member" "terraform_plan_log_writer" {
  project = "oss-vdb"
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.terraform_plan.email}"
}

resource "google_project_iam_member" "api_e2e_tester_log_writer" {
  project = "oss-vdb"
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.api_e2e_tester.email}"
}

resource "google_project_iam_member" "pr_ci_runner_log_writer" {
  project = "oss-vdb"
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.pr_ci_runner.email}"
}

resource "google_project_iam_member" "cloud_build_trigger_scheduler_editor" {
  project = "oss-vdb"
  role    = "roles/cloudbuild.builds.editor"
  member  = "serviceAccount:${google_service_account.cloud_build_trigger_scheduler.email}"
}

resource "google_project_iam_member" "pypi_publisher_log_writer" {
  project = "oss-vdb"
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.pypi_publisher.email}"
}

resource "google_project_iam_member" "pypa_triage_roles" {
  for_each = toset([
    "roles/bigquery.jobUser",
    "roles/logging.logWriter",
  ])

  project = "oss-vdb"
  role    = each.value
  member  = "serviceAccount:${google_service_account.pypa_triage.email}"
}

# ---------------------------------------------------------------------------
# Resource-Level IAM Bindings (Artifact Registry, Secret Manager, GCS)
# ---------------------------------------------------------------------------

resource "google_artifact_registry_repository_iam_member" "public_gcr_readers" {
  for_each = toset([
    "gcr.io",
    "us.gcr.io",
  ])

  project    = "oss-vdb"
  location   = "us"
  repository = each.value
  role       = "roles/artifactregistry.reader"
  member     = "allUsers"
}

resource "google_artifact_registry_repository_iam_member" "pr_ci_runner_gcr_reader" {
  project    = "oss-vdb"
  location   = "us"
  repository = "gcr.io"
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:${google_service_account.pr_ci_runner.email}"
}

resource "google_secret_manager_secret_iam_member" "pypi_publisher_secret_access" {
  project   = "oss-vdb"
  secret_id = "pypi-key"
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.pypi_publisher.email}"
}

resource "google_storage_bucket_iam_member" "pypa_triage_bucket_admin" {
  bucket = "pypa-advisory-db"
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.pypa_triage.email}"
}

resource "google_storage_bucket_iam_member" "terraform_plan_tfstate_lister" {
  bucket = "oss-vdb-tf"
  role   = "roles/storage.legacyBucketReader"
  member = "serviceAccount:${google_service_account.terraform_plan.email}"
}

resource "google_storage_bucket_iam_member" "terraform_plan_tfstate_viewer" {
  bucket = "oss-vdb-tf"
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.terraform_plan.email}"

  condition {
    title       = "PublicTerraformStateOnly"
    description = "Allows terraform-plan SA to read only oss-vdb and oss-vdb-test Terraform state, blocking access to private-osv and superosv state."
    expression  = "resource.name.startsWith(\"projects/_/buckets/oss-vdb-tf/objects/oss-vdb/\") || resource.name.startsWith(\"projects/_/buckets/oss-vdb-tf/objects/oss-vdb-test/\")"
  }
}

locals {
  env_kustomization_path  = "../../../clouddeploy/gke-workers/environments/oss-vdb-test"
  base_kustomization_path = "../../../clouddeploy/gke-workers/base"
  env_kustomization       = yamldecode(file("${local.env_kustomization_path}/kustomization.yaml"))
  base_kustomization      = yamldecode(file("${local.base_kustomization_path}/kustomization.yaml"))

  all_resources = concat(
    [for resource in local.env_kustomization.resources : "${local.env_kustomization_path}/${resource}" if can(regex("\\.yaml$", resource))],
    [for f in fileset(local.base_kustomization_path, "**/*.yaml") : "${local.base_kustomization_path}/${f}" if !endswith(f, "kustomization.yaml")],
  )

  # Iterate of each yaml configuration and create a key based on kind and name in the yaml file.
  # Break apart by --- first as default yamldecode does not support parsing multiple documents in a single file.
  kube_manifests = {
    for manifest in flatten([
      for file_path in local.all_resources : [
        # Split content by separator, creating a list of string documents
        for doc in split("\n---\n", file(file_path)) :
        yamldecode(doc)
        # Filter out empty strings caused by trailing separators
        if trimspace(doc) != ""
      ]
    ]) :
    "${try(manifest.kind, "")}--${try(manifest.metadata.name, "")}" => manifest
    if try(manifest.kind, "") == "CronJob"
  }
}

module "osv_pipeline" {
  source = "../../modules/osv_pipeline"

  project_id                                     = "oss-vdb-test"
  vulnerabilities_export_bucket                  = "osv-test-vulnerabilities"
  affected_commits_backups_bucket                = "osv-test-affected-commits"
  affected_commits_backups_bucket_retention_days = 2
  logs_bucket                                    = "osv-test-logs"

  extra_work_pools = [
    "reimport",
    "cves",
  ]

  cluster_location = "us-west2-b"

  postgres_tier              = "db-perf-optimized-N-4"
  postgres_availability_type = "ZONAL"
}

module "osv_test" {
  source = "../../modules/osv"

  project_id                    = "oss-vdb-test"
  worker_service_account_email  = module.osv_pipeline.worker_service_account_email
  vulnerabilities_export_bucket = module.osv_pipeline.vulnerabilities_export_bucket_name
  failed_tasks_topic_name       = module.osv_pipeline.failed_tasks_topic_name
  datastore_database_id         = module.osv_pipeline.datastore_database_id
  website_ingress               = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"

  public_import_logs_bucket     = "osv-test-public-import-logs"
  logs_bucket                   = "osv-test-logs"
  cve_osv_conversion_bucket     = "osv-test-cve-osv-conversion"
  debian_osv_conversion_bucket  = "osv-test-debian-osv"
  osv_dev_sitemap_bucket        = "test-osv-dev-sitemap"
  backups_bucket                = "osv-test-backup"
  backups_bucket_retention_days = 5

  website_domain = "test.osv.dev"

  indexer_configs_bucket = "osv-test-indexer-configs"
  indexer_repos_bucket   = "osv-test-indexer-repos"
}

module "osv_api" {
  source = "../../modules/osv_api"

  project_id                     = "oss-vdb-test"
  api_url                        = "api.test.osv.dev"
  esp_version                    = "2.57.1"
  gcs_log_dir                    = "gs://oss-vdb-tf/apply-logs"
  frontend_service_account_email = module.osv_test.frontend_service_account_email
  service_account_email          = module.osv_test.frontend_service_account_email

  postgres_primary_instance_name = module.osv_pipeline.postgres_instance_name
  postgres_region                = module.osv_pipeline.postgres_region
  postgres_read_pool_tier        = "db-perf-optimized-N-4"
  postgres_read_pool_node_count  = 1
}

# The test instance importer reads Android advisories from android-osv-test (configured in source_test.yaml)
resource "google_storage_bucket_iam_member" "worker_android_import" {
  bucket = "android-osv-test"
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${module.osv_pipeline.worker_service_account_email}"
}

module "k8s_cron_alert" {
  for_each                         = local.kube_manifests
  source                           = "../../modules/k8s_cron_alert"
  project_id                       = module.osv_test.project_id
  cronjob_name                     = each.value.metadata.name
  cronjob_expected_latency_minutes = lookup(each.value.metadata.labels, "cronLastSuccessfulTimeMins", null)
  notification_channel             = "projects/oss-vdb-test/notificationChannels/14282948683609643269"
}

import {
  to = module.osv_pipeline.google_firestore_database.datastore
  id = "oss-vdb-test/(default)"
}

import {
  to = module.osv_pipeline.google_compute_global_address.private_ip_address
  id = "projects/oss-vdb-test/global/addresses/google-managed-services-default"
}

import {
  to = module.osv_pipeline.google_service_networking_connection.private_vpc_connection
  id = "projects/oss-vdb-test/global/networks/default:servicenetworking.googleapis.com"
}

import {
  to = module.osv_test.google_service_account.frontend_sa
  id = "projects/oss-vdb-test/serviceAccounts/osv-frontend@oss-vdb-test.iam.gserviceaccount.com"
}

output "website_dns_records" {
  description = "DNS records that need to be created for the osv.dev website"
  value       = module.osv_test.website_dns_records
}

output "postgres_primary_private_ip" {
  description = "Private IP address of the primary Cloud SQL PostgreSQL instance"
  value       = module.osv_pipeline.postgres_private_ip_address
}

output "postgres_read_pool_private_ip" {
  description = "Private IP address of the Cloud SQL PostgreSQL read pool instance"
  value       = module.osv_api.read_pool_private_ip_address
}


terraform {
  backend "gcs" {
    bucket = "oss-vdb-tf"
    prefix = "oss-vdb-test"
  }

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 8.9.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 8.9.0"
    }
    external = {
      source  = "hashicorp/external"
      version = "~> 2.4.0"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.3.0"
    }
  }
}

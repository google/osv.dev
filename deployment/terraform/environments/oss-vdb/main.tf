locals {
  env_kustomization_path  = "../../../clouddeploy/gke-workers/environments/oss-vdb"
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

  project_id                                     = "oss-vdb"
  deployment_service_account_email               = "${google_service_account.deployment_service.account_id}@${google_service_account.deployment_service.project}.iam.gserviceaccount.com"
  vulnerabilities_export_bucket                  = "osv-vulnerabilities"
  public_export_bucket                           = true
  affected_commits_backups_bucket                = "osv-affected-commits"
  affected_commits_backups_bucket_retention_days = 3
  logs_bucket                                    = "osv-logs"

  extra_work_pools = [
    "reimport",
    "cves",
  ]

  create_oss_fuzz_subnet = true

  postgres_tier              = "db-perf-optimized-N-4"
  postgres_availability_type = "ZONAL"
}

module "osv" {
  source = "../../modules/osv"

  project_id                       = "oss-vdb"
  worker_service_account_email     = module.osv_pipeline.worker_service_account_email
  deployment_service_account_email = "${google_service_account.deployment_service.account_id}@${google_service_account.deployment_service.project}.iam.gserviceaccount.com"
  frontend_deployer_service_account_emails = [
    "${google_service_account.deployment_service.account_id}@${google_service_account.deployment_service.project}.iam.gserviceaccount.com",
    var.terraform_service_account_email,
  ]
  vulnerabilities_export_bucket = module.osv_pipeline.vulnerabilities_export_bucket_name
  failed_tasks_topic_name       = module.osv_pipeline.failed_tasks_topic_name
  datastore_database_id         = module.osv_pipeline.datastore_database_id
  website_ingress               = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"

  public_import_logs_bucket     = "osv-public-import-logs"
  cve_osv_conversion_bucket     = "cve-osv-conversion"
  debian_osv_conversion_bucket  = "debian-osv"
  logs_bucket                   = "osv-logs"
  osv_dev_sitemap_bucket        = "osv-dev-sitemap"
  backups_bucket                = "osv-backup"
  backups_bucket_retention_days = 60

  website_domain = "osv.dev"

  indexer_configs_bucket = "osv-indexer-configs"
  indexer_repos_bucket   = "osv-indexer-repos"
  public_buckets         = true
}

module "osv_api" {
  source = "../../modules/osv_api"

  project_id                     = "oss-vdb"
  api_url                        = "api.osv.dev"
  esp_version                    = "2.57.2"
  frontend_service_account_email = module.osv.frontend_service_account_email
  service_account_email          = module.osv.frontend_service_account_email

  postgres_primary_instance_name = module.osv_pipeline.postgres_instance_name
  postgres_region                = module.osv_pipeline.postgres_region
  postgres_read_pool_tier        = "db-perf-optimized-N-16"
  postgres_read_pool_node_count  = 2
}

module "oss_fuzz" {
  source                       = "../../modules/oss_fuzz"
  project_id                   = "oss-vdb"
  tasks_topic_id               = module.osv_pipeline.tasks_topic_id
  tasks_topic_name             = module.osv_pipeline.tasks_topic_name
  failed_tasks_topic_id        = module.osv_pipeline.failed_tasks_topic_id
  pubsub_service_account_email = module.osv_pipeline.pubsub_service_account_email
  subnetwork                   = module.osv_pipeline.oss_fuzz_subnet_self_link
  datastore_database_id        = module.osv_pipeline.datastore_database_id
  public_import_logs_bucket    = module.osv.public_import_logs_bucket_name
  oss_fuzz_export_bucket       = "oss-fuzz-osv-vulns"
}

# Production CI/CD deployment service account
resource "google_service_account" "deployment_service" {
  project      = "oss-vdb"
  account_id   = "deployment"
  display_name = "deployment"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_project_iam_member" "deployment_service" {
  project = "oss-vdb"
  role    = "roles/editor"
  member  = "serviceAccount:${google_service_account.deployment_service.email}"
}

# Cloud Router and NAT in us-central1 for private OSS-Fuzz workers cluster
resource "google_compute_router" "oss_fuzz_router" {
  project = "oss-vdb"
  name    = "router"
  network = "default"
  region  = "us-central1"
}

resource "google_compute_router_nat" "oss_fuzz_nat" {
  project                             = "oss-vdb"
  name                                = "nat-config"
  router                              = google_compute_router.oss_fuzz_router.name
  source_subnetwork_ip_ranges_to_nat  = "LIST_OF_SUBNETWORKS"
  nat_ip_allocate_option              = "AUTO_ONLY"
  region                              = google_compute_router.oss_fuzz_router.region
  enable_endpoint_independent_mapping = false

  subnetwork {
    name                    = module.osv_pipeline.oss_fuzz_subnet_self_link
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }

  log_config {
    enable = false
    filter = "ALL"
  }
}

module "k8s_cron_alert" {
  for_each                         = local.kube_manifests
  source                           = "../../modules/k8s_cron_alert"
  project_id                       = module.osv.project_id
  cronjob_name                     = each.value.metadata.name
  cronjob_expected_latency_minutes = lookup(each.value.metadata.labels, "cronLastSuccessfulTimeMins", null)
  notification_channel             = "projects/oss-vdb/notificationChannels/17648103713296264012"
}

import {
  to = module.osv_pipeline.google_firestore_database.datastore
  id = "oss-vdb/(default)"
}

import {
  to = google_compute_router.oss_fuzz_router
  id = "projects/oss-vdb/regions/us-central1/routers/router"
}

import {
  to = google_compute_router_nat.oss_fuzz_nat
  id = "projects/oss-vdb/regions/us-central1/routers/router/nat-config"
}

import {
  to = module.osv_pipeline.google_compute_global_address.private_ip_address
  id = "projects/oss-vdb/global/addresses/google-managed-services-default"
}

import {
  to = module.osv_pipeline.google_service_networking_connection.private_vpc_connection
  id = "projects/oss-vdb/global/networks/default:servicenetworking.googleapis.com"
}

output "website_dns_records" {
  description = "DNS records that need to be created for the osv.dev website"
  value       = module.osv.website_dns_records
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
    prefix = "oss-vdb"
  }
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 8.11.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 8.11.0"
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

variable "terraform_service_account_email" {
  type        = string
  description = "Service account used to apply Terraform changes (granted actAs on the frontend service account)."
  default     = "terraform-apply@oss-vdb.iam.gserviceaccount.com"
}

variable "impersonate_service_account" {
  type        = string
  description = "Service account to impersonate for local runs (pass empty string in CI where Cloud Build already runs as terraform-plan)."
  default     = "terraform-apply@oss-vdb.iam.gserviceaccount.com"
}

provider "google" {
  impersonate_service_account = var.impersonate_service_account != "" ? var.impersonate_service_account : null
}

provider "google-beta" {
  impersonate_service_account = var.impersonate_service_account != "" ? var.impersonate_service_account : null
}

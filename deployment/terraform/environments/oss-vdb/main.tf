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
  vulnerabilities_export_bucket                  = "osv-vulnerabilities"
  affected_commits_backups_bucket                = "osv-affected-commits"
  affected_commits_backups_bucket_retention_days = 3
  logs_bucket                                    = "osv-logs"

  extra_work_pools = [
    "reimport",
    "cves",
  ]

  create_oss_fuzz_subnet = true
}

module "osv" {
  source = "../../modules/osv"

  project_id                   = "oss-vdb"
  worker_service_account_email = module.osv_pipeline.worker_service_account_email

  public_import_logs_bucket     = "osv-public-import-logs"
  cve_osv_conversion_bucket     = "cve-osv-conversion"
  debian_osv_conversion_bucket  = "debian-osv"
  logs_bucket                   = "osv-logs"
  osv_dev_sitemap_bucket        = "osv-dev-sitemap"
  backups_bucket                = "osv-backup"
  backups_bucket_retention_days = 60
  gcs_log_dir                   = "gs://oss-vdb-tf/apply-logs"

  website_domain = "osv.dev"
  api_url        = "api.osv.dev"
  esp_version    = "2.55.3"

  indexer_configs_bucket = "osv-indexer-configs"
  indexer_repos_bucket   = "osv-indexer-repos"
}

module "oss_fuzz" {
  source                       = "../../modules/oss_fuzz"
  project_id                   = "oss-vdb"
  tasks_topic_id               = module.osv_pipeline.tasks_topic_id
  failed_tasks_topic_id        = module.osv_pipeline.failed_tasks_topic_id
  pubsub_service_account_email = module.osv_pipeline.pubsub_service_account_email
  subnetwork                   = module.osv_pipeline.oss_fuzz_subnet_self_link
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

output "website_dns_records" {
  description = "DNS records that need to be created for the osv.dev website"
  value       = module.osv.website_dns_records
}

terraform {
  backend "gcs" {
    bucket = "oss-vdb-tf"
    prefix = "oss-vdb"
  }
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.45.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 7.45.0"
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

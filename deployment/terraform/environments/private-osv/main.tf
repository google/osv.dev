module "osv_pipeline" {
  source = "../../modules/osv_pipeline"

  project_id                                 = "oss-vdb-test"
  datastore_name                             = "datastore-private"
  worker_service_account_id                  = "worker-private"
  vulnerabilities_export_bucket              = "osv-test-vulnerabilities-private"
  affected_commits_backups_bucket            = "osv-test-affected-commits-private"
  pubsub_topic_name                          = "private-tasks"
  pubsub_topic_failed_tasks_name             = "failed-private-tasks"
  pubsub_subscription_default_work_pool_name = "private-default-pool"
  pubsub_subscription_recovery_name          = "private-recovery"
  cluster_name                               = "workers-private"
  cluster_location                           = "us-central1-f"
  cluster_master_cidr                        = "172.16.0.80/28"
  gitter_disk_name                           = "gitter-disk-private"
  gitter_disk_size_gb                        = 6144
  importer_reconciler_git_cache_disk_name    = "importer-reconciler-git-cache-private"
  importer_reconciler_git_cache_size_gb      = 200
  subnet_name                                = "my-subnet-0-private"
  subnet_cidr                                = "10.45.80.0/22"
  router_name                                = "router-private"
  nat_name                                   = "nat-config-private"
}


terraform {
  backend "gcs" {
    bucket = "oss-vdb-tf"
    prefix = "private-osv"
  }
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.35.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 7.35.0"
    }
  }
}

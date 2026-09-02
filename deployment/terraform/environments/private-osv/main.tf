module "osv_pipeline" {
  source = "../../modules/osv_pipeline"

  project_id                                 = "private-osv"
  datastore_name                             = "(default)"
  worker_service_account_id                  = "worker-private"
  vulnerabilities_export_bucket              = "private-osv-vulnerabilities"
  affected_commits_backups_bucket            = "private-osv-affected-commits-backups"
  pubsub_topic_name                          = "osv-work"
  pubsub_topic_failed_tasks_name             = "failed-osv-work"
  pubsub_subscription_default_work_pool_name = "default"
  pubsub_subscription_recovery_name          = "recovery"
  cluster_name                               = "workers"
  cluster_location                           = "us-west2-c"
  cluster_master_cidr                        = "172.16.0.64/28"
  gitter_disk_name                           = "gitter-disk"
  gitter_disk_size_gb                        = 6144
  subnet_name                                = "osv-subnet"
  subnet_cidr                                = "10.44.0.0/20"
  router_name                                = "osv-router"
  nat_name                                   = "osv-nat-config"

  default_pool_res_size = 1
  highend_pool_res_size = 1
}


terraform {
  backend "gcs" {
    bucket = "oss-vdb-tf"
    prefix = "private-osv"
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
  }
}

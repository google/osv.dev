variable "deployment_service_account_email" {
  type        = string
  description = "CI/CD deployment service account email."
  default     = "deployment@oss-vdb.iam.gserviceaccount.com"
}

variable "terraform_service_account_email" {
  type        = string
  description = "Service account used to apply Terraform changes (granted actAs on the migrator service account)."
  default     = "terraform-apply@oss-vdb.iam.gserviceaccount.com"
}

module "osv_pipeline" {
  source = "../../modules/osv_pipeline"

  project_id                       = "private-osv"
  datastore_name                   = "(default)"
  worker_service_account_id        = "worker-private"
  deployment_service_account_email = var.deployment_service_account_email
  migrator_deployer_service_account_emails = compact([
    var.deployment_service_account_email,
    var.terraform_service_account_email,
  ])
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
  highend_pool_res_size = 2

  postgres_region               = "us-west2"
  postgres_tier                 = "db-perf-optimized-N-2"
  postgres_availability_type    = "ZONAL"
  postgres_migration_subnetwork = "osv-subnet"
}

# Kept scoped to private-osv (not shared osv_pipeline) so deployment@oss-vdb cannot actAs privileged SAs in oss-vdb
resource "google_project_iam_member" "deployment_service_account_user" {
  count   = var.deployment_service_account_email != "" ? 1 : 0
  project = "private-osv"
  role    = "roles/iam.serviceAccountUser"
  member  = "serviceAccount:${var.deployment_service_account_email}"
}


terraform {
  backend "gcs" {
    bucket = "oss-vdb-tf"
    prefix = "private-osv"
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
  }
}

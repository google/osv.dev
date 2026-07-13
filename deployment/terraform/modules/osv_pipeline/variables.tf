# Global & Database
variable "project_id" {
  type        = string
  description = "The GCP Project ID where resources will be provisioned."
}

variable "datastore_name" {
  type        = string
  description = "The name of the Datastore database instance. Default is '(default)'."
  default     = "(default)"
}

# Identity & Security
variable "worker_service_account_id" {
  type        = string
  description = "The ID to use for the GKE worker service account (max 30 characters)."
  default     = "osv-worker"
}

# Storage
variable "vulnerabilities_export_bucket" {
  type        = string
  description = "The name of the GCS bucket where vulnerability JSON and proto exports are stored."
}

variable "affected_commits_backups_bucket" {
  type        = string
  description = "The name of the GCS bucket where AffectedCommits database backups are stored."
}

variable "affected_commits_backups_bucket_retention_days" {
  type        = number
  description = "The number of days to retain GCS backups of AffectedCommits."
  default     = 30
}

# Messaging
variable "pubsub_topic_name" {
  type        = string
  description = "The name of the primary worker Pub/Sub task topic."
  default     = "tasks"
}

variable "pubsub_topic_failed_tasks_name" {
  type        = string
  description = "The name of the Pub/Sub topic for failed tasks (DLQ)."
  default     = "failed-tasks"
}

variable "pubsub_subscription_default_work_pool_name" {
  type        = string
  description = "The name of the default work pool Pub/Sub subscription."
  default     = "default-pool"
}

variable "pubsub_subscription_recovery_name" {
  type        = string
  description = "The name of the Pub/Sub subscription for task recovery."
  default     = "recovery"
}

variable "extra_work_pools" {
  type        = list(string)
  description = "Additional dynamic Pub/Sub worker pool subscriptions to create (e.g., reimport, cves)."
  default     = []
}

# Compute
variable "cluster_name" {
  type        = string
  description = "The name of the GKE cluster."
  default     = "workers"
}

variable "cluster_location" {
  type        = string
  description = "The GCP zone where the GKE cluster will be provisioned."
  default     = "us-central1-f"
}

variable "cluster_master_cidr" {
  type        = string
  description = "The private /28 IP range to allocate for the GKE master control plane peering."
  default     = "172.16.0.32/28"
}

variable "gitter_disk_name" {
  type        = string
  description = "The name of the persistent SSD disk for the gitter caching daemon."
  default     = "gitter-disk"
}

variable "gitter_disk_size_gb" {
  type        = number
  description = "The size in GiB of the persistent SSD disk used by the gitter caching daemon."
  default     = 6144 # 6TiB
}

variable "importer_reconciler_git_cache_disk_name" {
  type        = string
  description = "The name of the persistent SSD disk for the importer reconciler git cache."
  default     = "importer-reconciler-git-cache"
}

variable "importer_reconciler_git_cache_size_gb" {
  type        = number
  description = "The size in GiB of the persistent SSD disk used by the importer reconciler git cache."
  default     = 200
}

# Networking
variable "subnet_name" {
  type        = string
  description = "The name of the private subnet to create for GKE nodes."
  default     = "my-subnet-0"
}

variable "subnet_cidr" {
  type        = string
  description = "The IP range (CIDR) of the GKE private subnet. Must not overlap in the VPC."
  default     = "10.45.32.0/22"
}

variable "router_name" {
  type        = string
  description = "The name of the Cloud Router to create for GKE outbound traffic."
  default     = "router"
}

variable "nat_name" {
  type        = string
  description = "The name of the Cloud NAT configuration to create for GKE outbound traffic."
  default     = "nat-config"
}


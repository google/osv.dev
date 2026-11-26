variable "project_id" {
  type        = string
  description = "GCP Project ID."
}

variable "public_import_logs_bucket" {
  type        = string
  description = "Name of bucket to write importer logs to."
}

variable "logs_bucket" {
  type        = string
  description = "Name of bucket to export logs to."
}

variable "backups_bucket" {
  type        = string
  description = "Name of bucket to backup osv entries to."
}

variable "backups_bucket_retention_days" {
  type        = number
  description = "Number of days to retain osv backups"
}

variable "cve_osv_conversion_bucket" {
  type        = string
  description = "Name of bucket to store converted CVEs in."
}

variable "debian_osv_conversion_bucket" {
  type        = string
  description = "Name of bucket to store converted debian advisories in."
}

variable "osv_dev_sitemap_bucket" {
  type        = string
  description = "Name of bucket to store the osv.dev sitemap."
}

variable "website_domain" {
  type        = string
  description = "Domain to serve the OSV website on. Domain ownership and DNS settings must be manually configured."
}

variable "worker_service_account_email" {
  type        = string
  description = "The email of the GKE worker service account to grant access to OSV pipeline buckets and topics."
  default     = ""
}

variable "indexer_configs_bucket" {
  type        = string
  description = "Name of bucket storing indexer configuration."
  default     = ""
}

variable "indexer_repos_bucket" {
  type        = string
  description = "Name of bucket storing indexer repository data."
  default     = ""
}

variable "indexer_topic" {
  type        = string
  description = "Name of indexer Pub/Sub topic."
  default     = "indexer-work"
}

variable "indexer_subscription" {
  type        = string
  description = "Name of indexer Pub/Sub subscription."
  default     = "indexer-work-sub"
}

variable "vulnerabilities_export_bucket" {
  type        = string
  description = "Name of bucket storing exported vulnerability protos and JSONs."
}

variable "failed_tasks_topic_name" {
  type        = string
  description = "Name of the failed-tasks Pub/Sub topic."
}

variable "datastore_database_id" {
  type        = string
  description = "The resource ID of the Datastore database."
}

variable "website_ingress" {
  type        = string
  description = "Optional Cloud Run ingress setting for osv-website."
  default     = null
}

variable "deployment_service_account_email" {
  type        = string
  description = "Optional email of the CI/CD deployment service account granted Cloud Run deploy permissions."
  default     = ""
}

variable "frontend_deployer_service_account_emails" {
  type        = list(string)
  description = "Service account emails permitted to actAs the Cloud Run frontend service account during deployments."
  default     = []
}

variable "public_buckets" {
  type        = bool
  description = "Whether to grant allUsers public read access on public OSV feed, log, indexer config, and sitemap buckets."
  default     = false
}

variable "workload_identity_pool" {
  type        = string
  description = "Optional GKE Workload Identity pool (e.g. oss-vdb-test.svc.id.goog). When non-empty, provisions OSV-specific Workload Identity service accounts (osv-vulnfeeds)."
  default     = ""
}

variable "backup_service_account_email" {
  type        = string
  description = "Optional email of the backup Workload Identity service account to grant access to the Datastore backups bucket."
  default     = ""
}


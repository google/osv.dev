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

variable "api_url" {
  type        = string
  description = "URL to serve the OSV API on. Domain ownership and DNS settings has to be set up manually."
}

variable "esp_version" {
  type        = string
  description = "ESP version to use for OSV API frontend image."
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


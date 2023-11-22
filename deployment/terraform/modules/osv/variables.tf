variable "project_id" {
  type        = string
  description = "GCP Project ID."
}

variable "public_import_logs_bucket" {
  type        = string
  description = "Name of bucket to write importer logs to."
}

variable "vulnerabilities_export_bucket" {
  type        = string
  description = "Name of bucket to export vulnerabilities to."
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

variable "api_url" {
  type        = string
  description = "URL to serve the OSV API on. Domain ownership and DNS settings has to be set up manually."
}

variable "esp_version" {
  type        = string
  description = "ESP version to use for OSV API frontend image."
}

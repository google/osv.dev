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

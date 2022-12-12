variable "project_id" {
  type        = string
  description = "GCP Project ID."
}

variable "public_import_logs_bucket" {
  type        = string
  description = "Name of bucket to write importer logs to."
}

variable "resource_location" {
  type        = string
  description = "Location for multi-regional resources."
  default     = "US"
}

variable "resource_region" {
  type        = string
  description = "Region for regional resources."
  default     = "us-central1"
}

variable "worker_zone" {
  type        = string
  description = "Zone to use for workers."
  default     = "us-central1-f"
}
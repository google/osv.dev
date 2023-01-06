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

variable "api_url" {
  type        = string
  description = "URL to serve the OSV API on. Domain ownership and DNS settings has to be set up manually."
}

variable "api_backend_image_tag" {
  type        = string
  description = "Image tag of GRPC backend that should be deployed."
}
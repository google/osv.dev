variable "project_id" {
  type        = string
  description = "GCP Project ID."
}

variable "api_url" {
  type        = string
  description = "URL to serve the OSV API on. Domain ownership and DNS settings has to be set up manually."
}

variable "esp_version" {
  type        = string
  description = "ESP version to use for OSV API frontend image."
}

variable "_api_descriptor_file" {
  # This isn't actually sensitive, but it's outputted as a massive base64 string which really floods the plan output.
  sensitive = true
  type      = string
  default   = "api/api_descriptor.pb"
}

variable "gcs_log_dir" {
  type        = string
  description = "GCS directory to store cloud build logs."
  default     = ""
}

variable "postgres_primary_instance_name" {
  type        = string
  description = "Name of the primary Cloud SQL PostgreSQL instance to replicate from and create the read-only user on."
}

variable "postgres_read_pool_name" {
  type        = string
  description = "Name of the Cloud SQL PostgreSQL read pool instance."
  default     = "osv-db-read-pool"
}

variable "postgres_region" {
  type        = string
  description = "GCP region for the Cloud SQL read pool instance (must match the primary instance region)."
  default     = "us-central1"
}

variable "postgres_read_pool_tier" {
  type        = string
  description = "Machine tier for each node in the Cloud SQL Enterprise Plus read pool."
  default     = "db-perf-optimized-N-2"
}

variable "postgres_read_pool_node_count" {
  type        = number
  description = "Number of nodes in the Cloud SQL read pool."
  default     = 1
}

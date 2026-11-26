variable "project_id" {
  type        = string
  description = "GCP Project ID."
}

variable "region" {
  type        = string
  description = "GCP Region."
  default     = "us-central1"
}

variable "network" {
  type        = string
  description = "VPC Network name."
  default     = "default"
}
variable "tasks_topic_id" {
  type        = string
  description = "The ID of the tasks Pub/Sub topic."
}

variable "tasks_topic_name" {
  type        = string
  description = "The name of the tasks Pub/Sub topic."
}

variable "failed_tasks_topic_id" {
  type        = string
  description = "The ID of the failed-tasks Pub/Sub topic."
}

variable "pubsub_service_account_email" {
  type        = string
  description = "The email of the Pub/Sub service account."
}

variable "subnetwork" {
  type        = string
  description = "The self link of the subnetwork for oss-fuzz workers."
}

variable "datastore_database_id" {
  type        = string
  description = "The resource ID of the Datastore database (projects/<project>/databases/<db>)."
}

variable "public_import_logs_bucket" {
  type        = string
  description = "The name of the public import logs GCS bucket."
}

variable "oss_fuzz_export_bucket" {
  type        = string
  description = "The name of the OSS-Fuzz vulnerability export GCS bucket."
}

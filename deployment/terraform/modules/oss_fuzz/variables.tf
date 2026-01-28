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

variable "failed_tasks_topic_id" {
  type        = string
  description = "The ID of the failed-tasks Pub/Sub topic."
}

variable "pubsub_service_account_email" {
  type        = string
  description = "The email of the Pub/Sub service account."
}

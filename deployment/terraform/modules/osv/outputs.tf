output "project_id" {
  value       = var.project_id # Assuming you are using a variable for project_id within the module
  description = "The Google Cloud Project ID"
}
output "tasks_topic_id" {
  value       = google_pubsub_topic.tasks.id
  description = "The ID of the tasks Pub/Sub topic"
}

output "failed_tasks_topic_id" {
  value       = google_pubsub_topic.failed_tasks.id
  description = "The ID of the failed-tasks Pub/Sub topic"
}

output "pubsub_service_account_email" {
  value       = google_project_service_identity.pubsub.email
  description = "The email of the Pub/Sub service account"
}

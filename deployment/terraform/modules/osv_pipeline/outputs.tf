output "project_id" {
  value       = var.project_id
  description = "The Google Cloud Project ID"
}

output "tasks_topic_id" {
  value       = google_pubsub_topic.tasks.id
  description = "The ID of the tasks Pub/Sub topic"
}

output "tasks_topic_name" {
  value       = google_pubsub_topic.tasks.name
  description = "The name of the tasks Pub/Sub topic"
}

output "failed_tasks_topic_id" {
  value       = google_pubsub_topic.failed_tasks.id
  description = "The ID of the failed-tasks Pub/Sub topic"
}

output "failed_tasks_topic_name" {
  value       = google_pubsub_topic.failed_tasks.name
  description = "The name of the failed-tasks Pub/Sub topic"
}

output "pubsub_service_account_email" {
  value       = google_project_service_identity.pubsub.email
  description = "The email of the Pub/Sub service account"
}

output "worker_service_account_email" {
  value       = google_service_account.worker_sa.email
  description = "The email of the GKE worker service account"
}

output "oss_fuzz_subnet_self_link" {
  value       = one(google_compute_subnetwork.oss_fuzz_subnet[*].self_link)
  description = "The self link of the OSS-Fuzz subnetwork"
}

output "cluster_name" {
  value       = google_container_cluster.workers.name
  description = "The name of the GKE cluster"
}

output "cluster_location" {
  value       = google_container_cluster.workers.location
  description = "The location of the GKE cluster"
}

output "cluster_id" {
  value       = google_container_cluster.workers.id
  description = "The ID of the GKE cluster"
}

output "subnet_self_link" {
  value       = google_compute_subnetwork.my_subnet_0.self_link
  description = "The self link of the private subnetwork"
}

output "vulnerabilities_export_bucket_name" {
  value       = google_storage_bucket.osv_vulnerabilities_export.name
  description = "The name of the vulnerabilities export bucket"
}

output "affected_commits_backups_bucket_name" {
  value       = google_storage_bucket.affected_commits_backups_bucket.name
  description = "The name of the AffectedCommits backups bucket"
}

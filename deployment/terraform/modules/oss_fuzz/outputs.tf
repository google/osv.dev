output "cluster_name" {
  value = google_container_cluster.workers.name
}

output "cluster_endpoint" {
  value = google_container_cluster.workers.endpoint
}

output "cluster_location" {
  value = google_container_cluster.workers.location
}

output "node_service_account_email" {
  value       = google_service_account.node_sa.email
  description = "The email of the OSS-Fuzz GKE node service account."
}

output "metrics_adapter_service_account_email" {
  value       = google_service_account.metrics_adapter_sa.email
  description = "The email of the custom-metrics-stackdriver-adapter Workload Identity SA."
}

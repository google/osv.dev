output "cluster_name" {
  value = google_container_cluster.workers.name
}

output "cluster_endpoint" {
  value = google_container_cluster.workers.endpoint
}

output "cluster_location" {
  value = google_container_cluster.workers.location
}

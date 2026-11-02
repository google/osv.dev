output "read_pool_instance_name" {
  value       = google_sql_database_instance.read_pool.name
  description = "The name of the Cloud SQL PostgreSQL read pool instance."
}

output "read_pool_private_ip_address" {
  value       = google_sql_database_instance.read_pool.private_ip_address
  description = "The private IP address of the Cloud SQL PostgreSQL read pool instance."
}

output "read_pool_connection_name" {
  value       = google_sql_database_instance.read_pool.connection_name
  description = "The connection name of the Cloud SQL PostgreSQL read pool instance."
}

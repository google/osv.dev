output "project_id" {
  value       = var.project_id
  description = "The Google Cloud Project ID"
}

output "frontend_service_account_email" {
  value       = google_service_account.frontend_sa.email
  description = "The email of the dedicated Cloud Run frontend service account."
}

output "public_import_logs_bucket_name" {
  value       = google_storage_bucket.osv_public_import_logs.name
  description = "The name of the public import logs bucket."
}

output "project_id" {
  value       = var.project_id
  description = "The Google Cloud Project ID"
}

output "frontend_service_account_email" {
  value       = google_service_account.frontend_sa.email
  description = "The email of the dedicated Cloud Run frontend service account."
}

output "vanir_sandbox_uri" {
  value       = google_cloud_run_v2_service.vanir_sandbox.uri
  description = "The HTTPS URI of the vanir-sandbox Cloud Run service."
}


# Dedicated zero-privilege service account for the untrusted Vanir sandbox Cloud Run service.
# Intentionally granted ZERO IAM roles so querying the metadata server yields no GCP permissions.
resource "google_service_account" "vanir_sandbox" {
  project      = var.project_id
  account_id   = "vanir-sandbox"
  display_name = "Vanir Sandbox Service Account (zero IAM roles)"
}

# Allow CI/CD deployment and Terraform service accounts to attach vanir_sandbox to Cloud Run revisions.
# This grants permissions ON the service account to deployers, not TO the service account itself.
resource "google_service_account_iam_member" "vanir_sandbox_deployer_act_as" {
  for_each = toset([
    for email in var.frontend_deployer_service_account_emails : "serviceAccount:${email}"
  ])

  service_account_id = google_service_account.vanir_sandbox.name
  role               = "roles/iam.serviceAccountUser"
  member             = each.value
}

# Untrusted Cloud Run Gen2 microVM sandbox for running Vanir signature generation.
# Note: template is in lifecycle.ignore_changes, so Terraform only bootstraps the initial
# revision; deployment/clouddeploy/vanir-sandbox/run-{staging,prod}.yaml are the source of
# truth for runtime settings (zero-IAM SA, Gen2, concurrency=1, and no VPC access).
resource "google_cloud_run_v2_service" "vanir_sandbox" {
  project  = var.project_id
  name     = "vanir-sandbox"
  location = "us-west2"
  ingress  = "INGRESS_TRAFFIC_ALL"

  depends_on = [google_service_account_iam_member.vanir_sandbox_deployer_act_as]

  template {
    service_account                  = google_service_account.vanir_sandbox.email
    execution_environment            = "EXECUTION_ENVIRONMENT_GEN2"
    max_instance_request_concurrency = 1
    timeout                          = "1800s"

    scaling {
      min_instance_count = 0
      max_instance_count = 30
    }

    containers {
      image = "gcr.io/oss-vdb/vanir-sandbox:latest" # Placeholder image.
      resources {
        limits = {
          cpu    = "4"
          memory = "8Gi"
        }
      }
    }
  }

  lifecycle {
    ignore_changes = [
      # To be managed by Cloud Deploy.
      template,
      traffic,
      labels,
      client,
    ]
  }
}

# Restrict invocation strictly to the GKE worker service account (never allUsers).
resource "google_cloud_run_v2_service_iam_member" "vanir_sandbox_invoker" {
  count    = var.worker_service_account_email != "" ? 1 : 0
  project  = var.project_id
  location = google_cloud_run_v2_service.vanir_sandbox.location
  name     = google_cloud_run_v2_service.vanir_sandbox.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${var.worker_service_account_email}"
}

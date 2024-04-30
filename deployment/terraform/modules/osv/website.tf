resource "google_cloud_run_v2_service" "website" {
  project  = var.project_id
  name     = "osv-website"
  location = "us-west2"

  template {
    containers {
      image = "gcr.io/oss-vdb/osv-website:latest" # Placeholder image.
    }
  }

  lifecycle {
    ignore_changes = [
      # To be managed by Cloud Deploy.
      template,
      traffic,
      labels,
      client
    ]
    prevent_destroy = true
  }
}

# Allow unauthenticated access
resource "google_cloud_run_service_iam_binding" "website" {
  project  = var.project_id
  location = google_cloud_run_v2_service.website.location
  service  = google_cloud_run_v2_service.website.name
  role     = "roles/run.invoker"
  members = [
    "allUsers"
  ]
}

# TODO: Set up Google Cloud Load Balancing + Network Endpoint Group (NEG)
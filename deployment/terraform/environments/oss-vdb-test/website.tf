# TODO(michaelkedar):
# Temporary Terraform config to mirror the app engine onto Cloud Run for the test instance only
# Should be deleted and remade in the modules folder when formally moving away from App Engine
resource "google_cloud_run_v2_service" "website" {
  project  = "oss-vdb-test"
  name     = "osv-website"
  location = "us-west2"

  template {
    containers {
      image = "us-docker.pkg.dev/cloudrun/container/hello:latest" # Placeholder image.
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
    # prevent_destroy = true
  }
}

# Allow unauthenticated access
resource "google_cloud_run_service_iam_binding" "website" {
  project  = "oss-vdb-test"
  location = google_cloud_run_v2_service.website.location
  service  = google_cloud_run_v2_service.website.name
  role     = "roles/run.invoker"
  members = [
    "allUsers"
  ]
}

# TODO(michaelkedar): Native Cloud Run domain mapping does not work on us-west2
# Need to set up Google Cloud Load Balancing + Network Endpoint Group (NEG)
# (or move website + redis to a supported region)

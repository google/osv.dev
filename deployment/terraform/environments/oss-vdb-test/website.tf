# TODO(michaelkedar):
# Temporary Terraform config to mirror the app engine onto Cloud Run for the test instance only
# Should be deleted and remade in the modules folder when formally moving away from App Engine
resource "google_cloud_run_service" "website" {
  project  = "oss-vdb-test"
  name     = "osv-website"
  location = "us-west2"

  template {
    spec {
      containers {
        image = "us-docker.pkg.dev/cloudrun/container/hello:latest" # Placeholder image.
      }
    }
  }

  traffic {
    percent         = 100
    latest_revision = true
  }

  lifecycle {
    ignore_changes = [
      # To be managed by Cloud Deploy.
      template,
      traffic,
    ]
    # prevent_destroy = true
  }
}

resource "google_cloud_run_domain_mapping" "website" {
  project  = "oss-vdb-test"
  name     = "site.test.osv.dev"
  location = google_cloud_run_service.website.location
  metadata {
    namespace = "oss-vdb-test"
  }
  spec {
    route_name = google_cloud_run_service.website.name
  }
}
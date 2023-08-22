# Used to dynamically retrieve the project number.
data "google_project" "vdb" {
  project_id = var.project_id
}

# Give the cloud build in-built service account access to retrieve cloud endpoints config.
resource "google_project_iam_member" "project" {
  project    = var.project_id
  role       = "roles/servicemanagement.serviceController"
  member     = "serviceAccount:${data.google_project.vdb.number}@cloudbuild.gserviceaccount.com"
  depends_on = [google_project_service.cloud_build] // If the API is not enabled the default service account above does not exist yet.
}

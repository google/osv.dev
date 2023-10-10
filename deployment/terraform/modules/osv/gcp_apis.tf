# Required APIs
# TODO(michaelkedar): Check whether any required apis are missing.
# TODO(michaelkedar): Add depends_on to enable APIs before any resources are created.

resource "google_project_service" "cloudapis" {
  project            = var.project_id
  service            = "cloudapis.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "compute_engine_api" {
  project            = var.project_id
  service            = "compute.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "kubernetes_engine_api" {
  project            = var.project_id
  service            = "container.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "container_analysis" {
  project            = var.project_id
  service            = "containeranalysis.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "container_scanning" {
  project            = var.project_id
  service            = "containerscanning.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "redis_api" {
  project            = var.project_id
  service            = "redis.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "datastore_api" {
  project            = var.project_id
  service            = "datastore.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "vpcaccess_api" {
  project            = var.project_id
  service            = "vpcaccess.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "cloud_run_api" {
  project            = var.project_id
  service            = "run.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "service_management" {
  project            = var.project_id
  service            = "servicemanagement.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "service_control" {
  project            = var.project_id
  service            = "servicecontrol.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "endpoints" {
  project            = var.project_id
  service            = "endpoints.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "service_usage" {
  project            = var.project_id
  service            = "serviceusage.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "app_engine" {
  project            = var.project_id
  service            = "appengine.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "resource_manager" {
  project            = var.project_id
  service            = "cloudresourcemanager.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "cloud_build" {
  project            = var.project_id
  service            = "cloudbuild.googleapis.com"
  disable_on_destroy = false
}

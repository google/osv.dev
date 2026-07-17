# Datastore
resource "google_firestore_database" "datastore" {
  project     = var.project_id
  name        = var.datastore_name
  location_id = "us-west2"
  type        = "DATASTORE_MODE"
}

# GCP Bucket where protos and full JSON exports are stored
resource "google_storage_bucket" "osv_vulnerabilities_export" {
  project                     = var.project_id
  name                        = var.vulnerabilities_export_bucket
  location                    = "US"
  uniform_bucket_level_access = true

  versioning {
    enabled = true
  }

  lifecycle_rule {
    action {
      type = "Delete"
    }
    condition {
      num_newer_versions = 673
      with_state         = "ARCHIVED"
    }
  }

  lifecycle_rule {
    action {
      type = "Delete"
    }
    condition {
      days_since_noncurrent_time = 7
      with_state                 = "ANY"
    }
  }
}

# GCP bucket where affected commits are backed up.
resource "google_storage_bucket" "affected_commits_backups_bucket" {
  project                     = var.project_id
  name                        = var.affected_commits_backups_bucket
  location                    = "US"
  uniform_bucket_level_access = true
  lifecycle_rule {
    action {
      type = "Delete"
    }
    condition {
      age = var.affected_commits_backups_bucket_retention_days
    }
  }
}
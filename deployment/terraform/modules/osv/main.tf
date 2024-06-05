# osv.dev terraform configuration

# Datastore
resource "google_firestore_database" "datastore" {
  project     = var.project_id
  name        = "(default)"
  location_id = "us-west2"
  type        = "DATASTORE_MODE"

  lifecycle {
    # Destroying the resource doesn't seem to delete the database
    prevent_destroy = true
  }
}

# MemoryStore
resource "google_redis_instance" "frontend" {
  project            = var.project_id
  memory_size_gb     = 5
  name               = "redis-west2"
  read_replicas_mode = "READ_REPLICAS_ENABLED"
  redis_version      = "REDIS_6_X"
  region             = "us-west2"
  replica_count      = 1
  tier               = "STANDARD_HA"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_redis_instance" "central1" {
  project            = var.project_id
  memory_size_gb     = 16
  name               = "redis-central1"
  read_replicas_mode = "READ_REPLICAS_ENABLED"
  redis_version      = "REDIS_6_X"
  region             = "us-central1"
  replica_count      = 2
  tier               = "STANDARD_HA"

  lifecycle {
    prevent_destroy = true
  }
}

# Serverless VPC connector
resource "google_vpc_access_connector" "connector" {
  project        = var.project_id
  name           = "connector"
  network        = "default"
  region         = "us-west2"
  ip_cidr_range  = "10.8.0.0/28"
  max_throughput = 1000
}

# Storage Buckets
resource "google_storage_bucket" "osv_public_import_logs" {
  project                     = var.project_id
  name                        = var.public_import_logs_bucket
  location                    = "US"
  uniform_bucket_level_access = true

  lifecycle {
    prevent_destroy = true
  }

  lifecycle_rule {
    condition {
      num_newer_versions = 100
      with_state         = "ARCHIVED"
    }
    action {
      type = "Delete"
    }
  }

  lifecycle_rule {
    condition {
      days_since_noncurrent_time = 1
    }
    action {
      type = "Delete"
    }
  }

  versioning {
    enabled = true
  }
}

resource "google_storage_bucket" "osv_vulnerabilities_export" {
  project                     = var.project_id
  name                        = var.vulnerabilities_export_bucket
  location                    = "US"
  uniform_bucket_level_access = true

  lifecycle {
    prevent_destroy = true
  }

  logging {
    log_bucket        = var.logs_bucket
    log_object_prefix = "osv-vulnerabilities"
  }
}

resource "google_storage_bucket" "cve_osv_conversion" {
  project                     = var.project_id
  name                        = var.cve_osv_conversion_bucket
  location                    = "US"
  uniform_bucket_level_access = true

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_storage_bucket" "debian_osv_conversion_bucket" {
  project                     = var.project_id
  name                        = var.debian_osv_conversion_bucket
  location                    = "US"
  uniform_bucket_level_access = true

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_storage_bucket" "logs_bucket" {
  project                     = var.project_id
  name                        = var.logs_bucket
  location                    = "US"
  uniform_bucket_level_access = true

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_storage_bucket" "backups_bucket" {
  project                     = var.project_id
  name                        = var.backups_bucket
  location                    = "US"
  uniform_bucket_level_access = true
  lifecycle_rule {
    action {
      type = "Delete"
    }
    condition {
      age = var.backups_bucket_retention_days
    }
  }
  lifecycle {
    prevent_destroy = true
  }
}

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
  lifecycle {
    prevent_destroy = true
  }
}

# Service account permissions
resource "google_service_account" "deployment_service" {
  project      = var.project_id
  account_id   = "deployment"
  display_name = "deployment"
}

resource "google_project_iam_member" "deployment_service" {
  project = var.project_id
  role    = "roles/editor"
  member  = "serviceAccount:${google_service_account.deployment_service.email}"
}

# Datastore
resource "google_firestore_database" "datastore" {
  project     = var.project_id
  name        = var.datastore_name
  location_id = "us-west2"
  type        = "DATASTORE_MODE"

  lifecycle {
    prevent_destroy = true
  }
}

# Cloud SQL PostgreSQL Primary Instance
resource "google_project_service" "sqladmin" {
  project            = var.project_id
  service            = "sqladmin.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "secretmanager" {
  project            = var.project_id
  service            = "secretmanager.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "cloud_run" {
  project            = var.project_id
  service            = "run.googleapis.com"
  disable_on_destroy = false
}

resource "google_sql_database_instance" "postgres" {
  project             = var.project_id
  name                = var.postgres_instance_name
  database_version    = "POSTGRES_18"
  region              = var.postgres_region
  deletion_protection = true

  settings {
    edition                     = "ENTERPRISE_PLUS"
    tier                        = var.postgres_tier
    availability_type           = var.postgres_availability_type
    disk_autoresize             = true
    deletion_protection_enabled = true

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
    }

    data_cache_config {
      data_cache_enabled = true
    }

    connection_pool_config {
      connection_pooling_enabled = true

      flags {
        name  = "max_client_connections"
        value = "8000"
      }
      flags {
        name  = "query_wait_timeout"
        value = "10"
      }
    }

    ip_configuration {
      ipv4_enabled                                  = var.postgres_ipv4_enabled
      private_network                               = data.google_compute_network.default.id
      enable_private_path_for_google_cloud_services = true
      ssl_mode                                      = "ENCRYPTED_ONLY"
    }

    insights_config {
      query_insights_enabled = true
    }

    database_flags {
      name  = "cloudsql.iam_authentication"
      value = "on"
    }
    database_flags {
      name  = "temp_file_limit"
      value = "2147483647" # maximum allowed (2TiB, measured in KiB)
    }
  }

  depends_on = [
    google_project_service.sqladmin,
    google_service_networking_connection.private_vpc_connection,
  ]

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_sql_database" "osv" {
  project  = var.project_id
  instance = google_sql_database_instance.postgres.name
  name     = "osv"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_sql_user" "worker" {
  project  = var.project_id
  instance = google_sql_database_instance.postgres.name
  name     = "osv-worker"
  # Random bootstrap password; rotate via gcloud and store in Secret Manager after apply (see deployment/README.md).
  password       = uuid()
  database_roles = ["pg_read_all_data", "pg_write_all_data"]

  lifecycle {
    ignore_changes = [password]
  }

  depends_on = [google_sql_database.osv]
}

resource "google_sql_user" "deployment" {
  count          = var.deployment_service_account_email != "" ? 1 : 0
  project        = var.project_id
  instance       = google_sql_database_instance.postgres.name
  name           = trimsuffix(var.deployment_service_account_email, ".gserviceaccount.com")
  type           = "CLOUD_IAM_SERVICE_ACCOUNT"
  database_roles = ["cloudsqlsuperuser"]

  depends_on = [google_sql_user.worker]
}

resource "google_sql_user" "db_migrator" {
  project        = var.project_id
  instance       = google_sql_database_instance.postgres.name
  name           = trimsuffix(google_service_account.db_migrator.email, ".gserviceaccount.com")
  type           = "CLOUD_IAM_SERVICE_ACCOUNT"
  database_roles = ["cloudsqlsuperuser"]

  depends_on = [google_sql_user.deployment]
}

# VPC-connected Cloud Run Job that applies goose schema migrations over Cloud SQL Private IP.
resource "google_cloud_run_v2_job" "db_migrate" {
  project             = var.project_id
  name                = "osv-db-migrate"
  location            = var.postgres_region
  deletion_protection = false

  template {
    template {
      service_account = google_service_account.db_migrator.email
      max_retries     = 0
      timeout         = "600s"

      vpc_access {
        egress = "PRIVATE_RANGES_ONLY"
        network_interfaces {
          network    = "default"
          subnetwork = var.postgres_migration_subnetwork
        }
      }

      containers {
        image = "gcr.io/oss-vdb/goose:latest" # Placeholder; updated on deploy to goose-migrations:$COMMIT_SHA.

        env {
          name  = "CLOUDSQL_INSTANCE"
          value = google_sql_database_instance.postgres.connection_name
        }
        env {
          name  = "CLOUDSQL_PRIVATE_IP"
          value = "true"
        }
      }
    }
  }

  lifecycle {
    ignore_changes = [
      # Container image is updated per release by Cloud Build (build-and-stage.yaml / deploy-prod.yaml).
      template[0].template[0].containers[0].image,
      client,
      client_version,
    ]
  }

  depends_on = [
    google_project_service.cloud_run,
    google_compute_subnetwork.my_subnet_0,
    google_sql_user.db_migrator,
    google_project_iam_member.db_migrator_cloudsql_roles,
    google_service_account_iam_member.db_migrator_act_as,
  ]
}

resource "google_secret_manager_secret" "postgres_worker_password" {
  project   = var.project_id
  secret_id = "osv-db-worker-password"

  replication {
    auto {}
  }

  depends_on = [google_project_service.secretmanager]
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

  lifecycle {
    prevent_destroy = true
  }

  dynamic "logging" {
    for_each = var.logs_bucket != "" ? [1] : []
    content {
      log_bucket        = var.logs_bucket
      log_object_prefix = "osv-vulnerabilities"
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

  lifecycle {
    prevent_destroy = true
  }
}

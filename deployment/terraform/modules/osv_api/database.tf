# Cloud SQL PostgreSQL read pool and read-only credentials for the OSV API (and Website)

resource "google_project_service" "secretmanager" {
  project            = var.project_id
  service            = "secretmanager.googleapis.com"
  disable_on_destroy = false
}

data "google_compute_network" "default" {
  project = var.project_id
  name    = "default"
}

resource "google_sql_database_instance" "read_pool" {
  project              = var.project_id
  name                 = var.postgres_read_pool_name
  database_version     = "POSTGRES_18"
  region               = var.postgres_region
  master_instance_name = var.postgres_primary_instance_name
  instance_type        = "READ_POOL_INSTANCE"
  node_count           = var.postgres_read_pool_node_count
  deletion_protection  = true

  settings {
    edition                     = "ENTERPRISE_PLUS"
    tier                        = var.postgres_read_pool_tier
    disk_autoresize             = true
    deletion_protection_enabled = true

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
      ipv4_enabled                                  = false
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

  depends_on = [google_sql_user.readonly]
}

# PostgreSQL users are created on the primary instance and replicated via WAL to the read pool.
resource "google_sql_user" "readonly" {
  project  = var.project_id
  instance = var.postgres_primary_instance_name
  name     = "osv-readonly"
  # Random bootstrap password; rotate via gcloud and store in Secret Manager after apply (see deployment/README.md).
  password       = uuid()
  database_roles = ["pg_read_all_data"]

  lifecycle {
    ignore_changes = [password]
  }
}

resource "google_secret_manager_secret" "postgres_readonly_password" {
  project   = var.project_id
  secret_id = "osv-db-readonly-password"

  replication {
    auto {}
  }

  depends_on = [google_project_service.secretmanager]
}

resource "google_secret_manager_secret_iam_member" "frontend_readonly_secret_access" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.postgres_readonly_password.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${var.frontend_service_account_email}"
}

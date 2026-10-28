variable "project_id" {
  description = "The GCP project ID to deploy the experimental Cloud SQL database to."
  type        = string
  default     = "oss-vdb-test"
}

resource "google_sql_database_instance" "experiment" {
  project          = var.project_id
  name             = "experiment-db"
  database_version = "POSTGRES_18"
  region           = "us-west2"

  settings {
    tier              = "db-perf-optimized-N-16"
    availability_type = "ZONAL"

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
      ipv4_enabled                                  = true
      private_network                               = data.google_compute_network.default.id
      enable_private_path_for_google_cloud_services = true
      ssl_mode                                      = "ENCRYPTED_ONLY"
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

  deletion_protection = false
  depends_on          = [google_service_networking_connection.private_vpc_connection]
}

resource "google_sql_database" "osv" {
  name     = "osv"
  instance = google_sql_database_instance.experiment.name
  project  = var.project_id
}

resource "google_sql_user" "readonly" {
  project        = var.project_id
  instance       = google_sql_database_instance.experiment.name
  name           = "osv-readonly"
  password       = "change-me"
  database_roles = ["pg_read_all_data"]

  lifecycle {
    ignore_changes = [password]
  }
}

resource "google_secret_manager_secret" "postgres_readonly_password" {
  project   = var.project_id
  secret_id = "postgres-readonly-password"

  replication {
    auto {}
  }
}

data "google_compute_default_service_account" "default" {
  project = var.project_id
}

resource "google_secret_manager_secret_iam_member" "cloud_run_readonly_secret_access" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.postgres_readonly_password.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${data.google_compute_default_service_account.default.email}"
}

output "private_ip_address" {
  description = "Private IP address of the Cloud SQL instance for POSTGRES_HOST."
  value       = google_sql_database_instance.experiment.private_ip_address
}


resource "google_project_service" "service_networking" {
  project            = var.project_id
  service            = "servicenetworking.googleapis.com"
  disable_on_destroy = false
}

resource "google_compute_global_address" "private_ip_address" {
  project       = var.project_id
  name          = "google-managed-services-default"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = data.google_compute_network.default.id
}

resource "google_service_networking_connection" "private_vpc_connection" {
  network                 = data.google_compute_network.default.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_ip_address.name]

  depends_on = [google_project_service.service_networking]
}

data "google_compute_network" "default" {
  project = var.project_id
  name    = "default"
}

resource "google_logging_metric" "dualread_ds_duration" {
  project         = var.project_id
  name            = "dualread_ds_duration"
  description     = "Primary (Datastore/GCS) duration for API dual-read shadow comparisons."
  filter          = <<-EOT
    resource.type="cloud_run_revision"
    resource.labels.service_name=("osv-grpc-backend" OR "osv-grpc-backend-batch")
    severity="INFO"
    jsonPayload.message =~ "^DualRead "
  EOT
  value_extractor = "EXTRACT(jsonPayload.ds_duration)"

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "DISTRIBUTION"
    unit        = "ns"

    labels {
      key         = "op"
      value_type  = "STRING"
      description = "VulnerabilityStore operation name"
    }
    labels {
      key         = "ecosystem"
      value_type  = "STRING"
      description = "Package ecosystem (for MatchPackages)"
    }
    labels {
      key         = "versioned"
      value_type  = "BOOL"
      description = "Whether a version was specified (for MatchPackages)"
    }
  }

  label_extractors = {
    "op"        = "REGEXP_EXTRACT(jsonPayload.message, \"^DualRead (\\\\S+)\")"
    "ecosystem" = "EXTRACT(jsonPayload.ecosystem)"
    "versioned" = "EXTRACT(jsonPayload.versioned)"
  }

  bucket_options {
    exponential_buckets {
      num_finite_buckets = 60
      growth_factor      = 1.4
      scale              = 100000 # 0.1ms in nanoseconds
    }
  }
}

resource "google_logging_metric" "dualread_pg_duration" {
  project         = var.project_id
  name            = "dualread_pg_duration"
  description     = "Shadow (PostgreSQL) duration for API dual-read shadow comparisons."
  filter          = <<-EOT
    resource.type="cloud_run_revision"
    resource.labels.service_name=("osv-grpc-backend" OR "osv-grpc-backend-batch")
    severity="INFO"
    jsonPayload.message =~ "^DualRead "
  EOT
  value_extractor = "EXTRACT(jsonPayload.pg_duration)"

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "DISTRIBUTION"
    unit        = "ns"

    labels {
      key         = "op"
      value_type  = "STRING"
      description = "VulnerabilityStore operation name"
    }
    labels {
      key         = "ecosystem"
      value_type  = "STRING"
      description = "Package ecosystem (for MatchPackages)"
    }
    labels {
      key         = "versioned"
      value_type  = "BOOL"
      description = "Whether a version was specified (for MatchPackages)"
    }
  }

  label_extractors = {
    "op"        = "REGEXP_EXTRACT(jsonPayload.message, \"^DualRead (\\\\S+)\")"
    "ecosystem" = "EXTRACT(jsonPayload.ecosystem)"
    "versioned" = "EXTRACT(jsonPayload.versioned)"
  }

  bucket_options {
    exponential_buckets {
      num_finite_buckets = 60
      growth_factor      = 1.4
      scale              = 100000 # 0.1ms in nanoseconds
    }
  }
}

resource "google_logging_metric" "dualread_errors" {
  project     = var.project_id
  name        = "dualread_errors"
  description = "Count of failed PostgreSQL shadow reads in the API."
  filter      = <<-EOT
    resource.type="cloud_run_revision"
    resource.labels.service_name=("osv-grpc-backend" OR "osv-grpc-backend-batch")
    severity="WARNING"
    jsonPayload.message =~ "^DualRead .* failed$"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"

    labels {
      key         = "op"
      value_type  = "STRING"
      description = "VulnerabilityStore operation name"
    }
  }

  label_extractors = {
    "op" = "REGEXP_EXTRACT(jsonPayload.message, \"^DualRead (\\\\S+) failed$\")"
  }
}

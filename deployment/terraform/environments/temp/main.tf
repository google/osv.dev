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
    tier              = "db-perf-optimized-N-4"
    availability_type = "ZONAL"

    connection_pool_config {
      connection_pooling_enabled = true
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

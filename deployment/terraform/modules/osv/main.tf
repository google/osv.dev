# TODO(michaelkedar): Organise / refactor logically into multiple tf files
# and possibly add variables for some field values.

# APIs
# TODO(michaelkedar): Check whether any required apis are missing.
# TODO(michaelkedar): Add depends_on to enable APIs before any resources are created.

resource "google_project_service" "compute_engine_api" {
  project = var.project_id
  service = "compute.googleapis.com"
}

resource "google_project_service" "kubernetes_engine_api" {
  project = var.project_id
  service = "container.googleapis.com"
}

resource "google_project_service" "redis_api" {
  project = var.project_id
  service = "redis.googleapis.com"
}

resource "google_project_service" "datastore_api" {
  project = var.project_id
  service = "datastore.googleapis.com"
}

resource "google_project_service" "vpcaccess_api" {
  project = var.project_id
  service = "vpcaccess.googleapis.com"
}

resource "google_project_service" "cloud_run_api" {
  project = var.project_id
  service = "run.googleapis.com"
}

resource "google_project_service" "service_management" {
  project = var.project_id
  service = "servicemanagement.googleapis.com"
}

resource "google_project_service" "service_control" {
  project = var.project_id
  service = "servicecontrol.googleapis.com"
}

resource "google_project_service" "endpoints" {
  project = var.project_id
  service = "endpoints.googleapis.com"
}

# Network

resource "google_compute_subnetwork" "my_subnet_0" {
  project                  = var.project_id
  name                     = "my-subnet-0"
  network                  = "default"
  ip_cidr_range            = "10.45.32.0/22"
  private_ip_google_access = true
  region                   = var.resource_region
}

resource "google_compute_router" "router" {
  project = var.project_id
  name    = "router"
  network = "default"
  region  = var.resource_region
}

resource "google_compute_router_nat" "nat_config" {
  project                             = var.project_id
  name                                = "nat-config"
  router                              = google_compute_router.router.name
  source_subnetwork_ip_ranges_to_nat  = "ALL_SUBNETWORKS_ALL_IP_RANGES"
  nat_ip_allocate_option              = "AUTO_ONLY"
  region                              = google_compute_router.router.region
  enable_endpoint_independent_mapping = false
}


# Clusters / Node Pools

resource "google_container_cluster" "workers" {
  project    = var.project_id
  name       = "workers"
  location   = var.worker_zone
  subnetwork = google_compute_subnetwork.my_subnet_0.self_link

  private_cluster_config {
    enable_private_endpoint = false
    enable_private_nodes    = true
    master_ipv4_cidr_block  = "172.16.0.32/28"
  }

  # We need to define this for private clusters, but all fields are optional.
  ip_allocation_policy {}

  provider = google-beta
  addons_config {
    gce_persistent_disk_csi_driver_config {
      enabled = true
    }
  }

  # We can't create a cluster with no node pool defined, but we want to only use
  # separately managed node pools. So we create the smallest possible default
  # node pool and immediately delete it.
  remove_default_node_pool = true
  initial_node_count       = 1
}

resource "google_container_node_pool" "default_pool" {
  project  = var.project_id
  name     = "default-pool"
  cluster  = google_container_cluster.workers.name
  location = google_container_cluster.workers.location

  autoscaling {
    min_node_count = 1
    max_node_count = 1000
  }


  node_config {
    machine_type    = "n1-highmem-2"
    disk_type       = "pd-ssd"
    disk_size_gb    = 64
    local_ssd_count = 1

    oauth_scopes = ["https://www.googleapis.com/auth/cloud-platform"]

  }
}

resource "google_container_node_pool" "highend" {
  project  = var.project_id
  name     = "highend"
  cluster  = google_container_cluster.workers.name
  location = google_container_cluster.workers.location

  autoscaling {
    min_node_count = 0
    max_node_count = 100
  }


  node_config {
    machine_type    = "n1-standard-32"
    disk_type       = "pd-standard"
    disk_size_gb    = 100
    local_ssd_count = 1

    oauth_scopes = ["https://www.googleapis.com/auth/cloud-platform"]

    labels = {
      workloadType = "highend"
    }

    taint = [{
      effect = "NO_EXECUTE"
      key    = "workloadType"
      value  = "highend"
    }]

  }
}


# Pub/Sub topics

resource "google_pubsub_topic" "tasks" {
  project = var.project_id
  name    = "tasks"

  labels = {
    goog-dm = "pubsub"
  }
}

resource "google_pubsub_topic" "failed_tasks" {
  project = var.project_id
  name    = "failed-tasks"
}

resource "google_pubsub_subscription" "tasks" {
  project                    = var.project_id
  name                       = "tasks"
  topic                      = google_pubsub_topic.tasks.id
  message_retention_duration = "604800s"
  ack_deadline_seconds       = 600

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.failed_tasks.id
    max_delivery_attempts = 5
  }

  expiration_policy {
    ttl = "" # never expires
  }

  labels = {
    goog-dm = "pubsub"
  }
}

resource "google_pubsub_topic" "pypi_bridge" {
  project = var.project_id
  name    = "pypi-bridge"
}


# Service accounts permissions

data "google_compute_default_service_account" "default" {
  project = var.project_id
}

data "google_app_engine_default_service_account" "default" {
  project = var.project_id
}

resource "google_project_service_identity" "pubsub" {
  provider = google-beta
  project  = var.project_id
  service  = "pubsub.googleapis.com"
}

resource "google_project_iam_member" "compute_service" {
  project = var.project_id
  role    = "roles/editor"
  member  = "serviceAccount:${data.google_compute_default_service_account.default.email}"
}

resource "google_project_iam_member" "app_engine_service" {
  project = var.project_id
  role    = "roles/editor"
  member  = "serviceAccount:${data.google_app_engine_default_service_account.default.email}"
}

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

resource "google_pubsub_subscription_iam_member" "tasks_service_subscriber" {
  project      = var.project_id
  subscription = google_pubsub_subscription.tasks.name
  role         = "roles/pubsub.subscriber"
  member       = "serviceAccount:${google_project_service_identity.pubsub.email}"
}

resource "google_pubsub_topic_iam_member" "failed_tasks_service_publisher" {
  project = var.project_id
  topic   = google_pubsub_topic.failed_tasks.name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_project_service_identity.pubsub.email}"
}

# App Engine

resource "google_app_engine_application" "app" {
  project       = var.project_id
  location_id   = "us-west2"
  database_type = "CLOUD_DATASTORE_COMPATIBILITY"
}

# MemoryStore
resource "google_redis_instance" "west2" {
  project            = var.project_id
  memory_size_gb     = 5
  name               = "redis"
  read_replicas_mode = "READ_REPLICAS_ENABLED"
  redis_version      = "REDIS_6_X"
  region             = "us-west2"
  replica_count      = 1
  tier               = "STANDARD_HA"
  reserved_ip_range  = "10.126.238.64/28"
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
  reserved_ip_range  = "10.102.25.208/28"
}

# Serverless VPC connector
resource "google_vpc_access_connector" "connector" {
  project       = var.project_id
  name          = "connector"
  network       = "default"
  region        = "us-west2"
  ip_cidr_range = "10.8.0.0/28"
}

# Storage Buckets

# TODO(michaelkedar): naming of public buckets
resource "google_storage_bucket" "osv_public_import_logs" {
  project                     = var.project_id
  name                        = var.public_import_logs_bucket
  location                    = var.resource_location
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
}

resource "google_storage_bucket" "osv_vulnerabilities_export" {
  project                     = var.project_id
  name                        = var.vulnerabilities_export_bucket
  location                    = var.resource_location
  uniform_bucket_level_access = true

  lifecycle {
    prevent_destroy = true
  }
}
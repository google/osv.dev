resource "google_compute_subnetwork" "oss_fuzz_subnet" {
  project                  = var.project_id
  name                     = "oss-fuzz-subnet"
  network                  = var.network
  ip_cidr_range            = "10.45.36.0/22"
  private_ip_google_access = true
  region                   = var.region
}

resource "google_container_cluster" "workers" {
  project    = var.project_id
  name       = "oss-fuzz-workers"
  location   = "${var.region}-f"
  subnetwork = google_compute_subnetwork.oss_fuzz_subnet.self_link

  private_cluster_config {
    enable_private_endpoint = false
    enable_private_nodes    = true
    master_ipv4_cidr_block  = "172.16.0.48/28"
  }

  ip_allocation_policy {}

  addons_config {
    gce_persistent_disk_csi_driver_config {
      enabled = true
    }
  }

  remove_default_node_pool = true
  initial_node_count       = 1
  lifecycle {
    ignore_changes = [
      initial_node_count,
    ]
    prevent_destroy = true
  }

  monitoring_config {
    managed_prometheus {
      enabled = true
    }
  }
}

resource "google_container_node_pool" "workers_pool" {
  project  = var.project_id
  name     = "workers-pool"
  cluster  = google_container_cluster.workers.name
  location = google_container_cluster.workers.location

  lifecycle {
    replace_triggered_by = [
      google_container_cluster.workers.id,
    ]
  }

  autoscaling {
    min_node_count  = 1
    max_node_count  = 100
    location_policy = "BALANCED"
  }

  node_config {
    machine_type    = "n2-highmem-2"
    disk_type       = "pd-ssd"
    disk_size_gb    = 64
    local_ssd_count = 1

    oauth_scopes = ["https://www.googleapis.com/auth/cloud-platform"]

    labels = {
      workloadType = "workers-pool"
    }

    taint {
      effect = "NO_EXECUTE"
      key    = "workloadType"
      value  = "workers-pool"
    }
  }
}

resource "google_pubsub_subscription" "oss_fuzz_tasks" {
  project                    = var.project_id
  name                       = "oss-fuzz-tasks"
  topic                      = var.tasks_topic_id
  message_retention_duration = "604800s"
  ack_deadline_seconds       = 600

  dead_letter_policy {
    dead_letter_topic     = var.failed_tasks_topic_id
    max_delivery_attempts = 5
  }

  expiration_policy {
    ttl = "" # never expires
  }

  labels = {
    goog-dm = "pubsub"
  }

  filter = "attributes.type = \"regressed\" OR attributes.type = \"fixed\" OR attributes.type = \"impact\" OR attributes.type = \"invalid\" OR attributes.type = \"update-oss-fuzz\""
}

resource "google_pubsub_subscription_iam_member" "oss_fuzz_tasks_service_subscriber" {
  project      = var.project_id
  subscription = google_pubsub_subscription.oss_fuzz_tasks.name
  role         = "roles/pubsub.subscriber"
  member       = "serviceAccount:${var.pubsub_service_account_email}"
}

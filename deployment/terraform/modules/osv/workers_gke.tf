# GKE "workers" cluster and node pools

resource "google_container_cluster" "workers" {
  project    = var.project_id
  name       = "workers"
  location   = "us-central1-f"
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

# Service account permissions
data "google_compute_default_service_account" "default" {
  project = var.project_id
}

resource "google_project_iam_member" "compute_service" {
  project = var.project_id
  role    = "roles/editor"
  member  = "serviceAccount:${data.google_compute_default_service_account.default.email}"
}

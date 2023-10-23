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
  lifecycle {
    ignore_changes = [
      # importing from oss-vdb has initial_node_count set to 0, which is actually not a valid configuration for creating a cluster.
      # Updating this value in terraform forces a replacement, even though the default pool is destroyed. Ignore it to prevent disruption.
      initial_node_count,
    ]
    prevent_destroy = true
  }
}

resource "google_container_node_pool" "default_pool" {
  project  = var.project_id
  name     = "default-pool"
  cluster  = google_container_cluster.workers.name
  location = google_container_cluster.workers.location

  lifecycle {
    # Terraform doesn't automatically know to recreate node pools when the cluster is recreated.
    # A bit redundant since the cluster has prevent_destroy = true.
    replace_triggered_by = [
      google_container_cluster.workers.id,
    ]
  }

  autoscaling {
    min_node_count  = 1
    max_node_count  = 1000
    location_policy = "BALANCED"
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
  # For using the ephemeral storage local ssd config
  provider = google-beta

  lifecycle {
    # Terraform doesn't automatically know to recreate node pools when the cluster is recreated.
    # A bit redundant since the cluster has prevent_destroy = true.
    replace_triggered_by = [
      google_container_cluster.workers.id,
    ]
  }

  autoscaling {
    min_node_count  = 0
    max_node_count  = 100
    location_policy = "BALANCED"
  }


  node_config {
    machine_type = "n2-highmem-32"
    disk_type    = "pd-ssd"
    disk_size_gb = 100
    ephemeral_storage_config { // This is used for emptyDir storage in kubernetes
      // Minimum is 4 ssds for n2-highmem-32, for 375GB * 4 = 1.5TB of storage
      local_ssd_count = 4
    }

    oauth_scopes = ["https://www.googleapis.com/auth/cloud-platform"]

    labels = {
      workloadType = "highend"
    }

    taint {
      effect = "NO_EXECUTE"
      key    = "workloadType"
      value  = "highend"
    }

  }
}

resource "google_container_node_pool" "importer_pool" {
  project    = var.project_id
  name       = "importer-pool"
  cluster    = google_container_cluster.workers.name
  location   = google_container_cluster.workers.location
  node_count = 1

  lifecycle {
    # Terraform doesn't automatically know to recreate node pools when the cluster is recreated.
    # A bit redundant since the cluster has prevent_destroy = true.
    replace_triggered_by = [
      google_container_cluster.workers.id,
    ]
  }

  node_config {
    machine_type    = "n2-standard-2"
    disk_type       = "pd-ssd"
    disk_size_gb    = 64
    local_ssd_count = 1

    oauth_scopes = ["https://www.googleapis.com/auth/cloud-platform"]

    labels = {
      workloadType = "importer-pool"
    }

    taint {
      effect = "NO_EXECUTE"
      key    = "workloadType"
      value  = "importer-pool"
    }
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

# GKE "workers" cluster and node pools

resource "google_container_cluster" "workers" {
  project    = var.project_id
  name       = var.cluster_name
  location   = var.cluster_location
  subnetwork = google_compute_subnetwork.my_subnet_0.self_link

  private_cluster_config {
    enable_private_endpoint = false
    enable_private_nodes    = true
    master_ipv4_cidr_block  = var.cluster_master_cidr
  }

  # We need to define this for private clusters, but all fields are optional.
  ip_allocation_policy {}

  addons_config {
    gce_persistent_disk_csi_driver_config {
      enabled = true
    }
    gcp_filestore_csi_driver_config {
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
  }

  monitoring_service = "monitoring.googleapis.com/kubernetes"
  monitoring_config {
    enable_components = [
      "SYSTEM_COMPONENTS",
      "APISERVER",
      "SCHEDULER",
      "CONTROLLER_MANAGER",
      "STORAGE",
      "HPA",
      "POD",
      "DAEMONSET",
      "DEPLOYMENT",
      "STATEFULSET",
      "CADVISOR",
      "KUBELET"
    ]

    managed_prometheus {
      enabled = true
    }
  }
}

resource "google_container_node_pool" "default_pool" {
  project        = var.project_id
  name           = "default-pool"
  cluster        = google_container_cluster.workers.name
  location       = google_container_cluster.workers.location
  node_locations = var.node_pool_node_locations

  lifecycle {
    # Terraform doesn't automatically know to recreate node pools when the cluster is recreated.
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
    service_account = google_service_account.worker_sa.email
    machine_type    = "n4-standard-8"
    disk_type       = "hyperdisk-balanced"
    disk_size_gb    = 128

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
    service_account = google_service_account.worker_sa.email
    machine_type    = "n4-highmem-32"
    disk_type       = "hyperdisk-balanced"
    disk_size_gb    = 500

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

# 6TiB SSD disk used by the gitter caching service
resource "google_compute_disk" "gitter_disk" {
  project = var.project_id
  name    = var.gitter_disk_name
  type    = "hyperdisk-balanced"
  zone    = google_container_cluster.workers.location
  size    = var.gitter_disk_size_gb

  lifecycle {
    ignore_changes = [
      type,
      snapshot,
    ]
  }
}

# Reservations for N4 VMs so our infra can keep running in case of capacity issues
resource "google_compute_reservation" "default_pool_res" {
  project = var.project_id
  name    = "n4-standard-8-res"
  zone    = var.cluster_location
  reservation_sharing_policy {
    service_share_type = "ALLOW_ALL"
  }
  specific_reservation {
    count = var.default_pool_res_size
    instance_properties {
      machine_type = "n4-standard-8"
    }
  }
}

resource "google_compute_reservation" "highend_pool_res" {
  project = var.project_id
  name    = "n4-highmem-32-res"
  zone    = var.cluster_location
  reservation_sharing_policy {
    service_share_type = "ALLOW_ALL"
  }
  specific_reservation {
    count = var.highend_pool_res_size
    instance_properties {
      machine_type = "n4-highmem-32"
    }
  }
}
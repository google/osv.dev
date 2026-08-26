# Temporary resource to facilitate migrating ckuster to us-west2




resource "google_container_cluster" "workers_west" {
  project    = var.project_id
  name       = var.cluster_name
  location   = "us-west2-b"
  subnetwork = google_compute_subnetwork.my_subnet_west.self_link

  private_cluster_config {
    enable_private_endpoint = false
    enable_private_nodes    = true
    master_ipv4_cidr_block  = "172.16.0.64/28"
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

  monitoring_config {
    managed_prometheus {
      enabled = true
    }
  }
}

resource "google_container_node_pool" "default_pool_west" {
  project        = var.project_id
  name           = "default-pool"
  cluster        = google_container_cluster.workers_west.name
  location       = google_container_cluster.workers_west.location
  node_locations = ["us-west2-a", "us-west2-b", "us-west2-c"]

  lifecycle {
    # Terraform doesn't automatically know to recreate node pools when the cluster is recreated.
    replace_triggered_by = [
      google_container_cluster.workers_west.id,
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
    disk_size_gb    = 64

    oauth_scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }
}

resource "google_container_node_pool" "highend_west" {
  project        = var.project_id
  name           = "highend"
  cluster        = google_container_cluster.workers_west.name
  location       = google_container_cluster.workers_west.location
  node_locations = ["us-west2-a", "us-west2-b", "us-west2-c"]
  # For using the ephemeral storage local ssd config
  provider = google-beta

  lifecycle {
    # Terraform doesn't automatically know to recreate node pools when the cluster is recreated.
    replace_triggered_by = [
      google_container_cluster.workers_west.id,
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
resource "google_compute_disk" "gitter_disk_west" {
  project = var.project_id
  name    = var.gitter_disk_name
  type    = "hyperdisk-balanced"
  zone    = google_container_cluster.workers_west.location
  size    = var.gitter_disk_size_gb

  lifecycle {
    ignore_changes = [
      type,
      snapshot,
    ]
  }
}


resource "google_compute_subnetwork" "my_subnet_west" {
  project                  = var.project_id
  name                     = var.subnet_name
  network                  = "default"
  ip_cidr_range            = "10.44.0.0/20"
  private_ip_google_access = true
  region                   = "us-west2"

  lifecycle {
    ignore_changes = [
      description,
    ]
  }
}

# Cloud Router
# Required to route traffic for GKE nodes running on private IPs.
resource "google_compute_router" "router_west" {
  project = var.project_id
  name    = var.router_name
  network = "default"
  region  = "us-west2"
}

resource "google_compute_router_nat" "nat_config_west" {
  project                             = var.project_id
  name                                = var.nat_name
  router                              = google_compute_router.router_west.name
  source_subnetwork_ip_ranges_to_nat  = "LIST_OF_SUBNETWORKS"
  nat_ip_allocate_option              = "AUTO_ONLY"
  region                              = google_compute_router.router_west.region
  enable_endpoint_independent_mapping = false

  subnetwork {
    name                    = google_compute_subnetwork.my_subnet_west.id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }

  log_config {
    enable = false
    filter = "ALL"
  }
}

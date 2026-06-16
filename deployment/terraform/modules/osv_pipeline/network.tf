# Network configuration used by GKE worker nodes

# Private Subnetwork inside the "default" VPC network
# GKE nodes will be provisioned here and assigned private IPs.
resource "google_compute_subnetwork" "my_subnet_0" {
  project                  = var.project_id
  name                     = var.subnet_name
  network                  = "default"
  ip_cidr_range            = var.subnet_cidr
  private_ip_google_access = true
  region                   = "us-central1"

  lifecycle {
    ignore_changes = [
      description,
    ]
  }
}

# Cloud Router
# Required to route traffic for GKE nodes running on private IPs.
resource "google_compute_router" "router" {
  project = var.project_id
  name    = var.router_name
  network = "default"
  region  = "us-central1"
}

# Cloud NAT
# Allows private GKE nodes to securely access the public internet.
resource "google_compute_router_nat" "nat_config" {
  project                             = var.project_id
  name                                = var.nat_name
  router                              = google_compute_router.router.name
  source_subnetwork_ip_ranges_to_nat  = "ALL_SUBNETWORKS_ALL_IP_RANGES"
  nat_ip_allocate_option              = "AUTO_ONLY"
  region                              = google_compute_router.router.region
  enable_endpoint_independent_mapping = false

  log_config {
    enable = false
    filter = "ALL"
  }
}

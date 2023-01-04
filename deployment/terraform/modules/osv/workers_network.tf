# Network configuration used by workers

resource "google_compute_subnetwork" "my_subnet_0" {
  project                  = var.project_id
  name                     = "my-subnet-0"
  network                  = "default"
  ip_cidr_range            = "10.45.32.0/22"
  private_ip_google_access = true
  region                   = "us-central1"
}

resource "google_compute_router" "router" {
  project = var.project_id
  name    = "router"
  network = "default"
  region  = "us-central1"
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

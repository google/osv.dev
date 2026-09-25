# Move statements from temporary wild_west resources to primary resources
moved {
  from = google_container_cluster.workers_west
  to   = google_container_cluster.workers
}

moved {
  from = google_container_node_pool.default_pool_west
  to   = google_container_node_pool.default_pool
}

moved {
  from = google_container_node_pool.highend_west
  to   = google_container_node_pool.highend
}

moved {
  from = google_compute_disk.gitter_disk_west
  to   = google_compute_disk.gitter_disk
}

moved {
  from = google_compute_subnetwork.my_subnet_west
  to   = google_compute_subnetwork.my_subnet_0
}

moved {
  from = google_compute_router.router_west
  to   = google_compute_router.router
}

moved {
  from = google_compute_router_nat.nat_config_west
  to   = google_compute_router_nat.nat_config
}

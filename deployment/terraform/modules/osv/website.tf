# Website Cloud Run service
resource "google_cloud_run_v2_service" "website" {
  project  = var.project_id
  name     = "osv-website"
  location = "us-west2"

  template {
    containers {
      image = "gcr.io/oss-vdb/osv-website:latest" # Placeholder image.
    }
  }

  lifecycle {
    ignore_changes = [
      # To be managed by Cloud Deploy.
      template,
      traffic,
      labels,
      client
    ]
    prevent_destroy = true
  }
}

# Allow unauthenticated access
resource "google_cloud_run_service_iam_binding" "website" {
  project  = var.project_id
  location = google_cloud_run_v2_service.website.location
  service  = google_cloud_run_v2_service.website.name
  role     = "roles/run.invoker"
  members = [
    "allUsers"
  ]
}

# SSL Certificates
resource "google_certificate_manager_dns_authorization" "website" {
  project     = var.project_id
  name        = "website-dnsauth"
  description = "The dns auth for the osv.dev website"
  domain      = var.website_domain
}

resource "google_certificate_manager_certificate" "website" {
  project     = var.project_id
  name        = "website-cert"
  description = "The osv.dev website cert"
  managed {
    domains = [var.website_domain, "*.${var.website_domain}"]
    dns_authorizations = [
      google_certificate_manager_dns_authorization.website.id
    ]
  }
  lifecycle {
    replace_triggered_by = [google_certificate_manager_dns_authorization.website.id]
  }
}

resource "google_certificate_manager_certificate_map" "website" {
  project     = var.project_id
  name        = "website-certmap"
  description = "osv.dev website certificate map"
}

resource "google_certificate_manager_certificate_map_entry" "website" {
  project      = var.project_id
  name         = "website-certmap-entry"
  description  = "osv.dev website certificate map entry"
  map          = google_certificate_manager_certificate_map.website.name
  certificates = [google_certificate_manager_certificate.website.id]
  hostname     = var.website_domain

  lifecycle {
    replace_triggered_by = [google_certificate_manager_certificate_map.website.id, google_certificate_manager_certificate.website.id]
  }
}

# Load Balancer
module "gclb" {
  source  = "terraform-google-modules/lb-http/google//modules/serverless_negs"
  version = "~> 10.0"

  name    = "website"
  project = var.project_id

  enable_ipv6         = true
  create_ipv6_address = true
  ssl                 = true
  certificate_map     = google_certificate_manager_certificate_map.website.id

  load_balancing_scheme = "EXTERNAL_MANAGED"

  create_url_map = false
  url_map        = google_compute_url_map.website.id

  backends = {
    cloudrun = {
      groups = [
        {
          group = google_compute_region_network_endpoint_group.website_neg.id
        }
      ]
      protocol   = "HTTPS"
      enable_cdn = true
      cdn_policy = {
        cache_key_policy = {
          include_host         = true
          include_protocol     = true
          include_query_string = true
        }
        signed_url_cache_max_age_sec = 0
      }
      connection_draining_timeout_sec = 1

      iap_config = {
        enable = false
      }
      log_config = {
        enable = false
      }
    }
  }
}

resource "google_compute_region_network_endpoint_group" "website_neg" {
  project               = var.project_id
  name                  = "website-neg"
  network_endpoint_type = "SERVERLESS"
  region                = google_cloud_run_v2_service.website.location
  cloud_run {
    service = google_cloud_run_v2_service.website.name
  }
}

resource "google_compute_region_network_endpoint_group" "appengine_neg" {
  project               = var.project_id
  name                  = "appengine-neg"
  network_endpoint_type = "SERVERLESS"
  region                = google_app_engine_application.app.location_id
  app_engine {}
}

resource "google_compute_url_map" "website" {
  project         = var.project_id
  name            = "website-url-map"
  default_service = module.gclb.backend_services.cloudrun.id

  host_rule {
    hosts        = ["*"]
    path_matcher = "allpaths"
  }

  path_matcher {
    name            = "allpaths"
    default_service = module.gclb.backend_services.cloudrun.id
    route_rules {
      priority = 1
      match_rules {
        prefix_match = "/"
      }
      route_action {
        weighted_backend_services {
          backend_service = module.gclb.backend_services.cloudrun.id
          weight          = 100
        }
      }
    }
  }
}

# Output all the DNS records required for the website in one place. 
output "website_dns_records" {
  description = "DNS records that need to be created for the osv.dev website"
  value = concat([
    {
      data = module.gclb.external_ip
      name = "${var.website_domain}."
      type = "A"
    },
    {
      data = module.gclb.external_ipv6_address
      name = "${var.website_domain}."
      type = "AAAA"
  }], google_certificate_manager_dns_authorization.website.dns_resource_record)
}
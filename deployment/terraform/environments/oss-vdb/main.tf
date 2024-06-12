module "osv" {
  source = "../../modules/osv"

  project_id = "oss-vdb"

  public_import_logs_bucket                      = "osv-public-import-logs"
  vulnerabilities_export_bucket                  = "osv-vulnerabilities"
  cve_osv_conversion_bucket                      = "cve-osv-conversion"
  debian_osv_conversion_bucket                   = "debian-osv"
  logs_bucket                                    = "osv-logs"
  osv_dev_sitemap_bucket                         = "osv-dev-sitemap"
  backups_bucket                                 = "osv-backup"
  backups_bucket_retention_days                  = 60
  affected_commits_backups_bucket                = "osv-affected-commits"
  affected_commits_backups_bucket_retention_days = 3

  website_domain = "osv.dev"
  api_url        = "api.osv.dev"
  esp_version    = "2.47.0"
}

import {
  to = module.osv.google_firestore_database.datastore
  id = "oss-vdb/(default)"
}

output "website_dns_records" {
  description = "DNS records that need to be created for the osv.dev website"
  value       = module.osv.website_dns_records
}

terraform {
  backend "gcs" {
    bucket = "oss-vdb-tf"
    prefix = "oss-vdb"
  }
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.27.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.27.0"
    }
    external = {
      source  = "hashicorp/external"
      version = "~> 2.3.3"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2.2"
    }
  }
}

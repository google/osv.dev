module "osv" {
  source = "../../modules/osv"

  project_id = "oss-vdb"

  public_import_logs_bucket     = "osv-public-import-logs"
  vulnerabilities_export_bucket = "osv-vulnerabilities"
  cve_osv_conversion_bucket     = "cve-osv-conversion"
  debian_osv_conversion_bucket  = "debian-osv"
  logs_bucket                   = "osv-logs"
  backups_bucket                = "osv-backup"
  backups_bucket_retention_days = 60

  api_url     = "api.osv.dev"
  esp_version = "2.41.0"
}


terraform {
  backend "gcs" {
    bucket = "oss-vdb-tf"
    prefix = "oss-vdb"
  }
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.2.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.2.0"
    }
    external = {
      source  = "hashicorp/external"
      version = "~> 2.3.1"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2.1"
    }
  }
}

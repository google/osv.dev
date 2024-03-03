module "osv_test" {
  source = "../../modules/osv"

  project_id = "oss-vdb-test"

  public_import_logs_bucket                      = "osv-test-public-import-logs"
  vulnerabilities_export_bucket                  = "osv-test-vulnerabilities"
  logs_bucket                                    = "osv-test-logs"
  cve_osv_conversion_bucket                      = "osv-test-cve-osv-conversion"
  debian_osv_conversion_bucket                   = "osv-test-debian-osv"
  backups_bucket                                 = "osv-test-backup"
  backups_bucket_retention_days                  = 5
  affected_commits_backups_bucket                = "osv-test-affected-commits"
  affected_commits_backups_bucket_retention_days = 2

  api_url     = "api.test.osv.dev"
  esp_version = "2.41.0"
}


terraform {
  backend "gcs" {
    bucket = "oss-vdb-tf"
    prefix = "oss-vdb-test"
  }

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.8.0"
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

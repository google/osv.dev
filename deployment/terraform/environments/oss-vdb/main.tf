module "osv" {
  source = "../../modules/osv"

  project_id = "oss-vdb"

  public_import_logs_bucket     = "osv-public-import-logs"
  vulnerabilities_export_bucket = "osv-vulnerabilities"
  cve_osv_conversion_bucket     = "cve-osv-conversion"
  debian_osv_conversion_bucket  = "debian-osv"

  api_url     = "api.osv.dev"
  esp_version = "2.41.0"
}


terraform {
  backend "gcs" {
    bucket = "oss-vdb-tf"
    prefix = "oss-vdb"
  }
}

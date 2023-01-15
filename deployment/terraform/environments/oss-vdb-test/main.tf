module "osv_test" {
  source = "../../modules/osv"

  project_id = "oss-vdb-test"

  public_import_logs_bucket     = "osv-test-public-import-logs"
  vulnerabilities_export_bucket = "osv-test-vulnerabilities"
  cve_osv_conversion_bucket = "cve-osv-conversion"

  api_url               = "api.test.osv.dev"
  api_backend_image_tag = "20230105"
}


terraform {
  backend "gcs" {
    bucket = "oss-vdb-tf"
    prefix = "oss-vdb-test"
  }
}

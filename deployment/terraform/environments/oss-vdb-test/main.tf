module "osv_test" {
  source = "../../modules/osv"

  project_id = "oss-vdb-test"

  public_import_logs_bucket  = "osv-test-public-import-logs"
  osv_vulnerabilities_bucket = "osv-test-vulnerabilities"

  resource_location = "US"
  resource_region   = "us-central1"
  worker_zone       = "us-central1-f"
}


terraform {
  backend "gcs" {
    bucket = "oss-vdb-tf"
    prefix = "oss-vdb-test"
  }
}

# API server

The API server runs on Cloud Run with Cloud Endpoints.

The Cloud Endpoints configuration is managed through terraform.

Deployments of API backend is done through Cloud Deploy (`deployment/clouddeploy/osv-api`).

# Contributing:

Note: Running the API locally (via `make run-api-server` and `make api-server-tests`) requires GCP authentication to fetch the configuration from the `oss-vdb` project. See also `v1/README.md`.

## Writing tests
To speed up running tests:

1. `make run-api-server` at the root of this repository to start the test server.
2. `poetry shell` in this directory
3. `python -m unittest integration_test.py` in this directory.

This avoids the need to start the test server (and waiting for it) every run.
# Goose Cloud Builder & Migration Image

Used for running PostgreSQL schema migrations (`goose`) via Cloud SQL Auth Proxy (`cloud-sql-proxy`), both directly and inside the `osv-db-migrate` Cloud Run Job (`build-and-stage.yaml` and `deploy-prod.yaml`). Contains `goose`, `cloud-sql-proxy`, and `gcloud`.

To build and push the base builder image, run from this directory:
```bash
gcloud builds submit --project=oss-vdb --config=cloudbuild.yaml
```

During CI (`build-and-stage.yaml`), `docker/goose/Dockerfile.migrations` bundles `go/internal/database/postgres/migrations/` on top of this base image into `gcr.io/oss-vdb/goose-migrations:$COMMIT_SHA`, which is then executed by the VPC-connected `osv-db-migrate` Cloud Run Job.

## Environment Variables

When `CLOUDSQL_INSTANCE` is set, `entrypoint.bash` starts `cloud-sql-proxy --auto-iam-authn` in the background, waits for its readiness probe, connects as the active GCP identity (resolved from the GCE/Cloud Run metadata server, falling back to `gcloud auth list`) with `role=cloudsqlsuperuser`, and runs `goose`:

* `CLOUDSQL_INSTANCE`: Cloud SQL connection name (`project:region:instance`).
* `CLOUDSQL_PRIVATE_IP`: Set to `true` to pass `--private-ip` to `cloud-sql-proxy` (used inside the VPC-connected `osv-db-migrate` Cloud Run Job).
* `PGROLE`: PostgreSQL session role set at startup (default: `cloudsqlsuperuser`; set to empty string to disable).

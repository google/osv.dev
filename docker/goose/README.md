# Goose Migrations Runner Image

Base image for running PostgreSQL schema migrations (`goose`) via Cloud SQL Auth Proxy (`cloud-sql-proxy`). Used by the `osv-db-migrate` Cloud Run Job across `oss-vdb-test`, `oss-vdb`, and `private-osv` via `docker/goose/migrations.Dockerfile` (`gcr.io/oss-vdb/goose-migrations`). Contains `goose`, `cloud-sql-proxy`, and `gcloud`.

To build and push the base image, run from this directory:
```bash
gcloud builds submit --project=oss-vdb --config=cloudbuild.yaml
```

Environment variables handled by `entrypoint.bash`:
- `CLOUDSQL_INSTANCE`: Cloud SQL connection name (`project:region:instance`). When set, starts `cloud-sql-proxy --auto-iam-authn` in the background, waits for its readiness probe, sets `GOOSE_DRIVER`/`GOOSE_DBSTRING`, and executes `goose "$@"`.
- `CLOUDSQL_PRIVATE_IP`: Set to `"true"` to pass `--private-ip` to `cloud-sql-proxy` (required inside a VPC against private-IP-only Cloud SQL instances).
- `PGUSER`: Override the PostgreSQL IAM user (e.g., `osv-migrator@<project>.iam`); defaults to the active `gcloud` account with `.gserviceaccount.com` stripped.
- `PGDATABASE`: Target database name (defaults to `osv`).

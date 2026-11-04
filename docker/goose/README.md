# Goose Cloud Builder Image

Used for running PostgreSQL schema migrations (`goose`) via Cloud SQL Auth Proxy (`cloud-sql-proxy`) in Cloud Build (`build-and-stage.yaml` and `deploy-prod.yaml`). Contains `goose`, `cloud-sql-proxy`, and `gcloud`.

To build and push the builder image, run from this directory:
```bash
gcloud builds submit --project=oss-vdb --config=cloudbuild.yaml
```

Afterwards, it can be used in Cloud Build as:
```yaml
steps:
- name: gcr.io/oss-vdb/goose
  env: ['CLOUDSQL_INSTANCE=oss-vdb-test:us-central1:osv-db']
  args: ['up']
  dir:  go/internal/database/postgres/migrations
```

When `CLOUDSQL_INSTANCE` is set, the entrypoint starts `cloud-sql-proxy --auto-iam-authn` in the background, waits for its readiness probe, connects as the active Cloud Build IAM user (`deployment@oss-vdb.iam`) with `role=cloudsqlsuperuser`, and runs `goose`.

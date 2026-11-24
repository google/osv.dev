# GCP Project Setup (WIP)

## API Domain Name

Due to [terraform complexities](https://github.com/hashicorp/terraform-provider-google/issues/5528),
setting up the OSV API requires a custom domain to serve it on.

For example, if you own `custom-domain.name` and wish to serve the api on `api.custom-domain.name`:

1. Verify the ownership of your domain:
  
    Go to 

    `https://www.google.com/webmasters/verification/verification?authuser=0&domain=custom-domain.name`

    (Replace `custom-domain.name` in the url with the actual domain to be verified.)
    
    (This link is usually generated when adding a domain mapping to a service in Cloud Run.
    I don't know how to navigate to that page otherwise. Trying to add a property from
    [Webmaster Central](https://www.google.com/webmasters/verification/home)
    adds it as a site, rather than as a domain.)

2. Add DNS CNAME record mapping `api.custom-domain.name` to `ghs.googlehosted.com.`

## Terraform

Go to the relevant directory `/deployment/terraform/environments/<PROJECT_ID>`:

Initialise terraform:
```bash
terraform init
```
This command only needs to be run once to first set up the terraform directory,
though it is safe to run multiple times.

Plan and apply required project infrastructure:
```bash
terraform plan
```
Running `plan` shows the what resources will be added, changed, and destroyed
when applying the terraform configuration. It is not strictly necessary to run,
but it is useful to perform a sanity check before applying.

```bash
terraform apply
```
Running `apply` will also output the same added/changed/destroyed resources as
`plan`, and will prompt if you wish to apply the proposed changes.

Always review the planned changes (especially the destroyed resources) before
applying them. Some changes may cause terraform to unexpectedly destroy and
recreate resources.

Use `terraform plan` and `terraform apply` to deploy any configuration changes.

Terraform is automatically run on `oss-vdb-test` in `build-and-stage.yaml`

### Cloud SQL PostgreSQL Passwords

Because database user passwords are kept out of Terraform state (`ignore_changes = [password]`), Terraform initializes SQL users with a random bootstrap password (`uuid()`) and creates empty Secret Manager secrets. After the initial `terraform apply` creates `osv-db`, generate and store the real passwords once per project:

```bash
PROJECT_ID="oss-vdb-test" # or "oss-vdb" / "private-osv"

# Set worker password (all environments: oss-vdb, oss-vdb-test, private-osv)
PG_WORKER_PASS=$(openssl rand -hex 24)
gcloud sql users set-password osv-worker \
  --instance=osv-db \
  --project="$PROJECT_ID" \
  --password="$PG_WORKER_PASS"
printf "%s" "$PG_WORKER_PASS" | gcloud secrets versions add osv-db-worker-password \
  --project="$PROJECT_ID" \
  --data-file=-
unset PG_WORKER_PASS

# Set read-only API password (public environments with osv_api: oss-vdb, oss-vdb-test)
PG_RO_PASS=$(openssl rand -hex 24)
gcloud sql users set-password osv-readonly \
  --instance=osv-db \
  --project="$PROJECT_ID" \
  --password="$PG_RO_PASS"
printf "%s" "$PG_RO_PASS" | gcloud secrets versions add osv-db-readonly-password \
  --project="$PROJECT_ID" \
  --data-file=-
unset PG_RO_PASS
```

### Cloud SQL PostgreSQL Schema Migrations & IAM Access

Cloud SQL instances use `ssl_mode = "ENCRYPTED_ONLY"`; `osv-db-read-pool` is **private IP only** (`ipv4_enabled = false`), and `osv-db` defaults to `postgres_ipv4_enabled = true` only while `osv-db-migrate` and the `pg-tunnel` GKE deployment are rolled out and verified (flip `postgres_ipv4_enabled` to `false` once confirmed).

Database schema migrations live in `go/internal/database/postgres/migrations/` and are managed with [goose](https://github.com/pressly/goose). Each commit to `master` builds `gcr.io/oss-vdb/goose-migrations:$COMMIT_SHA` (via `docker/goose/migrations.Dockerfile` layered on `gcr.io/oss-vdb/goose:latest`).

* **Staging (`oss-vdb-test`)**: Applied automatically by `build-and-stage.yaml` right after `terraform apply` by updating and executing the private `osv-db-migrate` Cloud Run Job (`gcloud run jobs execute osv-db-migrate --wait`).
* **Production (`oss-vdb` & `private-osv`)**: Applied automatically by `deploy-prod.yaml` at the release `$COMMIT_SHA` via the `osv-db-migrate` Cloud Run Jobs right before promoting the Cloud Deploy pipelines.

After the initial `terraform apply` creates the `osv-migrator@<project>.iam` Cloud SQL user on an instance, set its default login role to `cloudsqlsuperuser` once per instance (so tables created by CI/CD migrations are owned by the shared `cloudsqlsuperuser` role):

```bash
# In one terminal, open a tunnel through the project's GKE `workers` cluster:
make run-pg-tunnel-staging   # or make run-pg-tunnel / make run-pg-tunnel-private

# In another terminal, impersonate osv-migrator so it alters its own role
# (PostgreSQL 16+/18 hardened CREATEROLE rules disallow altering another role without ADMIN OPTION):
PGSSLMODE=require PGPASSWORD=$(gcloud sql generate-login-token \
  --impersonate-service-account="osv-migrator@${PROJECT_ID}.iam.gserviceaccount.com") \
  psql -h 127.0.0.1 -p 5432 -U "osv-migrator@${PROJECT_ID}.iam" -d osv \
  -c "ALTER ROLE \"osv-migrator@${PROJECT_ID}.iam\" SET role = 'cloudsqlsuperuser';"
```

To connect or run `goose` manually from your workstation via IAM authentication (no public IP required):

1. Ensure `kubectl` is installed alongside `gcloud`.
2. Create a Cloud SQL IAM user for your Google account (once per instance):
   ```bash
   gcloud sql users create "$(gcloud config get-value account)" \
     --instance=osv-db \
     --project="$PROJECT_ID" \
     --type=CLOUD_IAM_USER \
     --database-roles=cloudsqlsuperuser
   ```
3. Port-forward to the loopback-only `socat` tunnel `Deployment` inside the `workers` cluster (`pg-tunnel` for `osv-db`, `pg-tunnel-read-pool` for `osv-db-read-pool`; port `5432` = direct Postgres, `6432` = Managed Connection Pooling):
   ```bash
   make run-pg-tunnel-staging   # oss-vdb-test primary (:5432)
   # or make run-pg-tunnel      # oss-vdb primary (:5432)
   # or make run-pg-tunnel TARGET=pg-tunnel-read-pool REMOTE_PORT=6432
   # or make run-pg-tunnel-private
   ```
   Or directly with `kubectl` (if your context is already pointing at the cluster):
   ```bash
   kubectl port-forward -n default deploy/pg-tunnel 5432:5432
   ```
   *(For local sessions longer than ~1 hour, IAM tokens from `gcloud sql generate-login-token` expire — connect as `osv-readonly` with `gcloud secrets versions access latest --secret=osv-db-readonly-password` instead. To also verify the database server certificate against the instance CA instead of `sslmode=require`, fetch it with `gcloud sql instances describe osv-db --project="$PROJECT_ID" --format='value(serverCaCert.cert)' > /tmp/osv-db-ca.pem` and pass `PGSSLMODE=verify-ca PGSSLROOTCERT=/tmp/osv-db-ca.pem`.)*
4. Set your IAM user's default login role to `cloudsqlsuperuser` (once per instance):
   ```bash
   PGSSLMODE=require PGPASSWORD=$(gcloud sql generate-login-token) \
     psql -h 127.0.0.1 -p 5432 -U "$(gcloud config get-value account)" -d osv \
     -c "ALTER ROLE \"$(gcloud config get-value account)\" SET role = 'cloudsqlsuperuser';"
   ```
5. Check migration status via `osv-db-migrate`:
   ```bash
   # Use --region=us-west2 for private-osv
   gcloud run jobs execute osv-db-migrate \
     --project="$PROJECT_ID" \
     --region=us-central1 \
     --args=status \
     --wait
   ```
   Or run `goose` locally through the tunnel:
   ```bash
   goose -dir go/internal/database/postgres/migrations postgres \
     "host=127.0.0.1 port=5432 user=$(gcloud config get-value account) password=$(gcloud sql generate-login-token) dbname=osv sslmode=require default_query_exec_mode=cache_describe" \
     status
   ```

> **Reverting migrations**: In production, prefer pushing a new forward-fix migration PR rather than rolling back history. For immediate rollbacks of an additive migration, run `gcloud run jobs execute osv-db-migrate --project="$PROJECT_ID" --region=us-central1 --args=down --wait` (use `--region=us-west2` for `private-osv`), which executes the `-- +goose Down` block of the latest version, then revert the migration file in git.


## Setting up auto-scaler

There doesn't seem to be a good way to set this up within terraform.

The following instructions are from [here](https://cloud.google.com/kubernetes-engine/docs/tutorials/external-metrics-autoscaling#step1).

```bash
kubectl create clusterrolebinding cluster-admin-binding \
    --clusterrole cluster-admin --user "$(gcloud config get-value account)"
```

```bash
kubectl apply -f https://raw.githubusercontent.com/GoogleCloudPlatform/k8s-stackdriver/master/custom-metrics-stackdriver-adapter/deploy/production/adapter_new_resource_model.yaml
```

On clusters with GKE Workload Identity enabled (such as `oss-fuzz-workers`), the adapter's `custom-metrics/custom-metrics-stackdriver-adapter` ServiceAccount must carry the `iam.gke.io/gcp-service-account` annotation bound to a GCP ServiceAccount with `roles/monitoring.viewer` (for `oss-fuzz-workers`, this is managed declaratively in `deployment/clouddeploy/oss-fuzz-workers/service-accounts.yaml`).

## Build and deploy remote builds to `oss-vdb-test`

Done automatically with Cloud Deploy, as part of `build-and-stage.yaml`, which is triggered on pushes to the master branch.

The Cloud Deploy pipelines are set up in the `oss-vdb` project.


### Manual builds / deployment

Not really supported, but theoretically possible.

Building locally would involve running `docker build` and `docker push` for the respective Dockerfiles, as in `build-and-stage.yaml`.

Manual deployment without Cloud Deploy would involve manually changing Kubernetes or Cloud Run manifests found in `clouddeploy/` to suit needs, replacing the Cloud Deploy image names with actual container images.


## Quotas

It doesn't look like GCP Quota increase requests can be automated.

Things that have been manually set on `oss-vdb-test`:
- Compute Engine
  - CPUs => 1000
  - Local SSD => 100 TB
  - Pesistent Disk SSD => 50 TB

## Setting up additional Cloud Deploy pipelines

To setup additional pipelines, you need to create another directory within `clouddeploy/`, with a `clouddeploy.yaml` and `skaffold.yaml` file, as well as the manifest files.

Easiest method would be to copy the structure in `gke-indexer/` (GKE) or `osv-api` (Cloud Run). You can also refer to the [Cloud Deploy quickstarts](https://cloud.google.com/deploy/docs/quickstarts)

NOTE: The `targetId` fields in the `clouddeploy.yaml` files should be unique across all pipelines.

To create the pipeline in GCP, run the following inside the new Cloud Deploy directory:

```
gcloud deploy apply --file=clouddeploy.yaml --region=us-central1 --project=oss-vdb
```

Then you need to add entries into `build-and-stage.yaml` to build/tag the required images and create a new deployment onto the staging environment (with the image name substitutions), as well as an entry to `deploy-prod.yaml` to do the promotion from staging to prod when releasing.
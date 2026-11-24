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

### PR Terraform Plan Service Account (`terraformPlanReader`)

Pull requests that touch `deployment/terraform/**` trigger `deployment/terraform/cloudbuild-tf-plan.yaml` as `terraform-plan@oss-vdb.iam.gserviceaccount.com`. To minimize blast radius on PR branches, this service account does **not** hold `roles/viewer` or `roles/iam.securityReviewer`; instead it holds:

- Custom role `projects/<project>/roles/terraformPlanReader` on `oss-vdb` and `oss-vdb-test` — strictly the control-plane `.get` and `.getIamPolicy` permissions needed to refresh managed Terraform resources (no write permissions, no `datastore.entities.*`, no `storage.objects.get` across project buckets, no `cloudsql.backupRuns.export`, no `secretmanager.versions.access`).
- `roles/logging.logWriter` on `oss-vdb` (for Cloud Build `CLOUD_LOGGING_ONLY`).
- `roles/storage.legacyBucketReader` + prefix-conditioned `roles/storage.objectViewer` (`PublicTerraformStateOnly`) on `gs://oss-vdb-tf`, restricted to `oss-vdb/` and `oss-vdb-test/` state prefixes only (blocks reading `private-osv/` and `superosv/` state).

**When adding a new GCP resource type or data source to Terraform**, if the PR `terraform-plan` check fails with `403 PermissionDenied`:

1. Identify the missing read-only `.get` or `.getIamPolicy` permission from the Cloud Build log (avoid data-plane read, export, or write permissions).
2. Add the permission to `google_project_iam_custom_role.terraform_plan_reader` in `deployment/terraform/environments/oss-vdb/ci_iam.tf`.
3. Update the live custom role in **both** `oss-vdb` and `oss-vdb-test` so PR `terraform-plan` can pass immediately (in `oss-vdb-test`, `deployment@oss-vdb` intentionally does not hold `roles/iam.roleAdmin`, so the role definition is referenced via `data "google_project_iam_custom_role"` and updated out-of-band):
   ```bash
   for PROJECT in oss-vdb oss-vdb-test; do
     gcloud iam roles update terraformPlanReader \
       --project="$PROJECT" \
       --add-permissions="<missing.permission.get>" \
       --quiet
   done
   ```
4. Re-run the `terraform-plan (oss-vdb)` PR check to verify both `oss-vdb-test` and `oss-vdb` plans pass.

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

Database schema migrations live in `go/internal/database/postgres/migrations/` and are managed with [goose](https://github.com/pressly/goose).

* **Staging (`oss-vdb-test`)**: Applied automatically by `build-and-stage.yaml` right after `terraform apply` using the `gcr.io/oss-vdb/goose` Cloud Builder image (see `docker/goose/`).
* **Production (`oss-vdb` & `private-osv`)**: Applied automatically by `deploy-prod.yaml` at the release `$COMMIT_SHA` right before promoting the Cloud Deploy pipelines.

After the initial `terraform apply` creates the `deployment@oss-vdb.iam` Cloud SQL user on an instance, set its default login role to `cloudsqlsuperuser` once per instance (so tables created by CI/CD migrations are owned by the shared `cloudsqlsuperuser` role):

```bash
# In one terminal (use us-central1 for oss-vdb / oss-vdb-test, or us-west2 for private-osv):
cloud-sql-proxy "${PROJECT_ID}:us-central1:osv-db" \
  --auto-iam-authn \
  --impersonate-service-account=deployment@oss-vdb.iam.gserviceaccount.com

# In another terminal:
psql "host=127.0.0.1 port=5432 user=deployment@oss-vdb.iam dbname=osv sslmode=disable" \
  -c 'ALTER ROLE "deployment@oss-vdb.iam" SET role = '\''cloudsqlsuperuser'\'';'
```

To connect or run `goose` manually from your workstation via IAM authentication:

1. Install `cloud-sql-proxy` (via `gcloud components install cloud-sql-proxy`, `go install github.com/GoogleCloudPlatform/cloud-sql-proxy/v2@latest`, or the [standalone binary](https://cloud.google.com/sql/docs/postgres/connect-instance-auth-proxy#install)).
2. Create a Cloud SQL IAM user for your Google account (once per instance):
   ```bash
   gcloud sql users create "$(gcloud config get-value account)" \
     --instance=osv-db \
     --project="$PROJECT_ID" \
     --type=CLOUD_IAM_USER \
     --database-roles=cloudsqlsuperuser
   ```
3. Start `cloud-sql-proxy` with automatic IAM authentication (or via `make run-cloud-sql-proxy-staging` / `make run-cloud-sql-proxy`):
   ```bash
   # Use us-central1 for oss-vdb / oss-vdb-test, or us-west2 for private-osv
   cloud-sql-proxy "${PROJECT_ID}:us-central1:osv-db" --auto-iam-authn
   ```
4. Set your IAM user's default login role to `cloudsqlsuperuser` (once per instance):
   ```bash
   psql "host=127.0.0.1 port=5432 user=$(gcloud config get-value account) dbname=osv sslmode=disable" \
     -c "ALTER ROLE \"$(gcloud config get-value account)\" SET role = 'cloudsqlsuperuser';"
   ```
5. Run `goose`:
   ```bash
   goose -dir go/internal/database/postgres/migrations postgres \
     "host=127.0.0.1 port=5432 user=$(gcloud config get-value account) dbname=osv sslmode=disable default_query_exec_mode=cache_describe" \
     status
   ```

> **Reverting migrations**: In production, prefer pushing a new forward-fix migration PR rather than rolling back history. For immediate rollbacks of an additive migration, you can connect via `cloud-sql-proxy` and run `goose ... down` (which executes the `-- +goose Down` block of the latest version), then revert the migration file in git.


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
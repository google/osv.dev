# Experimental PostgreSQL Terraform Setup

Temporary Terraform configuration for provisioning the experimental Cloud SQL for PostgreSQL instance (`experiment-db`), read-only database user (`osv-readonly`), Secret Manager secret (`postgres-readonly-password`), and `dualread_*` Cloud Logging metrics.

## 1. Apply Terraform

For `oss-vdb-test` (default):

```bash
terraform init
terraform apply
```

For `oss-vdb` (using a separate workspace so state files don't collide):

```bash
terraform workspace select -or-create prod
terraform apply -var="project_id=oss-vdb"
```

## 2. Set the `osv-readonly` Password & Secret Manager Version

Because the password is not managed in Terraform state (`ignore_changes = [password]`), generate a random password and set it on both the Cloud SQL user and Secret Manager after running `terraform apply`:

```bash
PROJECT_ID="oss-vdb-test" # or "oss-vdb"

PG_PASS=$(openssl rand -hex 24)
gcloud sql users set-password osv-readonly \
  --instance=experiment-db \
  --project="$PROJECT_ID" \
  --password="$PG_PASS"
printf "%s" "$PG_PASS" | gcloud secrets versions add postgres-readonly-password \
  --project="$PROJECT_ID" \
  --data-file=-
unset PG_PASS
```

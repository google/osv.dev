# Cloud Deploy Pipeline Set Up
To create the pipeline:
```
gcloud deploy apply --file=clouddeploy.yaml --region=us-central1 --project=oss-vdb
```
The same command is used to update the pipeline if `clouddeploy.yaml` changes. 

Pipelines are uniquely identified by their `name` metadata field - if it's changed a new pipeline would be created and the old one would have to be deleted.

`targetId` needs to be different between pipelines, otherwise it gets overwritten.

## Kubernetes Secrets

GKE worker workloads (`workers`, `workers-cves`, `workers-reimport`, `relations`, `vanir-signatures`) read `POSTGRES_PASSWORD` from a Kubernetes `Secret` named `osv-db-worker-password` (key: `password`).

Before deploying or after rotating the `osv-worker` Cloud SQL password in Secret Manager, sync the secret into the target GKE cluster:
```bash
PROJECT_ID="oss-vdb-test" # or "oss-vdb" / "private-osv"
CLUSTER_ZONE="us-west2-b" # use "us-west2-c" for oss-vdb and private-osv

gcloud container clusters get-credentials workers \
  --zone="$CLUSTER_ZONE" \
  --project="$PROJECT_ID"

kubectl create secret generic osv-db-worker-password \
  --from-literal="password=$(gcloud secrets versions access latest --secret=osv-db-worker-password --project="$PROJECT_ID")" \
  --dry-run=client -o yaml | kubectl apply -f -

# When rotating the password, restart the long-running worker Deployments so pods pick up
# the updated POSTGRES_PASSWORD env var (CronJobs pick it up automatically on their next run):
kubectl rollout restart deployment workers workers-cves workers-reimport # (or just `workers` in private-osv)
```

## Deletion
To delete the pipeline:
```
gcloud deploy delete --file=clouddeploy.yaml --force --region=us-central1 --project=oss-vdb
```

This does *not* delete the deployed workloads/instances, they would have to be manually removed.

Cloud Deploy also creates a GCP bucket for its pipelines that stores the rollout data, which should also be removed. The bucket names are long alphanumeric identifiers, with a `_clouddeploy` suffix. Not sure how to tell which bucket belongs to which pipeline...

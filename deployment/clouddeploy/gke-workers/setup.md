# Cloud Deploy Pipeline Set Up
To create the pipeline:
```
gcloud deploy apply --file=clouddeploy.yaml --region=us-central1 --project=oss-vdb
```
The same command is used to update the pipeline if `clouddeploy.yaml` changes. 

Pipelines are uniquely identified by their `name` metadata field - if it's changed a new pipeline would be created and the old one would have to be deleted.

## Deletion
To delete the pipeline:
```
gcloud deploy delete --file=clouddeploy.yaml --force --region=us-central1 --project=oss-vdb
```

This does *not* delete the deployed workloads/instances, they would have to be manually removed.

Cloud Deploy also creates a GCP bucket for its pipelines that stores the rollout data, which should also be removed. The bucket names are long alphanumeric identifiers, with a `_clouddeploy` suffix. Not sure how to tell which bucket belongs to which pipeline...

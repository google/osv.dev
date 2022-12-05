# GCP Project Setup (WIP)

Ensure the `GOOGLE_CLOUD_PROJECT` environment variable is exported for the project:
```bash
export GOOGLE_CLOUD_PROJECT=<PROJECT_ID>
```
The official project id of OSV is `oss-vdb`.

## Terraform

In this directory (`/deployment`):

Initialise terraform:
```bash
terraform init
```

Plan and apply required project infastructure:
```bash
terraform plan
```
```bash
terraform apply
```
Use these commands to deploy any configuration changes.
Inspect the proposed changes when running the command to see what resources will
be added, modified and destroyed.

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

## Submit local builds to container registry

Currently, only worker is implemented.

If `GOOGLE_CLOUD_PROJECT` is not set, the project ID will default to `oss-vdb`.

Inside `docker/worker-base/`
```bash
./build.sh <TAG>
```

Then, inside `docker/worker/`
```bash
./build.sh <TAG>
```

## Deploy builds to cluster

First, edit the image path in `deployment/oss-vdb-test/cloudbuild/gke/workers/workers.yaml` to match the project ID:

```yaml
        # gcr.io/<PROJECT_ID>/[...] must match the build project id.
        # TODO(michaelkedar): Investigate dynamically setting this.
        image: gcr.io/<PROJECT_ID>/worker:latest
```

e.g. for `oss-vdb-test`:
```yaml
        image: gcr.io/oss-vdb-test/worker:latest
```

Then, inside `deployment/oss-vdb-test/cloudbuild/`

```bash
gcloud beta builds submit . --project=<PROJECT_ID> --substitutions=COMMIT_SHA=<TAG>
```

This might time out if running the first time on a newly-created cluster.
It seems to trigger an auto-repair on the cluster. Running the command again
after the auto-repair finishes should work correctly.

## Still TODO
- Refactor terraform files.
- Investigate running terraform on existing GCP project.
  - May require `terraform import`-ing all existing resources.
- Deployments (and required terraform configs) for importer, indexer, etc.
- Properly update existing build/deploy process to take project id as an input.
- Configuring `SourceRepository` in datastore.
- Configuring secrets.

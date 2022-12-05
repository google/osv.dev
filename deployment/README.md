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
This command only needs to be run once to first set up the terraform directory,
though it is safe to run multiple times.

Plan and apply required project infastructure:
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
        # TODO(michaelkedar): Investigate dynamically setting this. [kustomize]
        image: gcr.io/<PROJECT_ID>/worker:latest
```

e.g. for `oss-vdb-test`:
```yaml
        image: gcr.io/oss-vdb-test/worker:latest
```

(TODO: Do this automatically with [kustomize](https://kubernetes.io/docs/tasks/manage-kubernetes-objects/kustomization/))

Then, inside `deployment/oss-vdb-test/cloudbuild/`

```bash
gcloud beta builds submit . --project=<PROJECT_ID> --substitutions=COMMIT_SHA=<TAG>
```

This might time out if running the first time on a newly-created cluster.
It seems to trigger an auto-repair on the cluster. Running the command again
after the auto-repair finishes should work correctly.

## Still TODO
- Refactor terraform files.
  - https://cloud.google.com/docs/terraform/best-practices-for-terraform may be helpful
- Investigate running terraform on existing GCP project.
  - May require `terraform import`-ing all existing resources.
- Deployments (and required terraform configs) for importer, indexer, etc.
- Properly update existing build/deploy process to take project id as an input.
- Configuring `SourceRepository` in datastore.
- Configuring secrets.
- Configuring Cloud Memorystore Redis instance

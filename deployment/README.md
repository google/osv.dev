# GCP Project Setup (WIP)

Ensure the `GOOGLE_CLOUD_PROJECT` environment variable is exported for the project:
```bash
export GOOGLE_CLOUD_PROJECT=<PROJECT_ID>
```
The official project id of OSV is `oss-vdb`.

## Terraform

Go to the relevant directory `/deployment/terraform/environments/<PROJECT_ID>`:

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

## Build and deploy remote builds to oss-vdb-test
Inside `deployment/oss-vdb-test/k8s/`, run

```bash
./deploy.sh <COMMIT_SHA>
```

Replacing <COMMIT_SHA> with the hash of the commit in google/osv.dev to deploy.


## Submit local builds to container registry

Currently, worker, importer and exporter are implemented.

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

First, edit the image path in `deployment/oss-vdb-test/k8s/gke/workers/workers.yaml`, `.../gke/importer/importer.yaml`, and `.../gke/exporter/exporter.yaml` to match the project ID:

```yaml
        # in worker.yaml
        image: gcr.io/<PROJECT_ID>/worker:latest

        # in importer.yaml
        image: gcr.io/<PROJECT_ID>/importer:latest

        # in exporter.yaml
        image: gcr.io/<PROJECT_ID>/exporter:latest
```

e.g. for `oss-vdb-test`:
```yaml
        image: gcr.io/oss-vdb-test/worker:latest
```

(TODO: Do this automatically with [kustomize](https://kubernetes.io/docs/tasks/manage-kubernetes-objects/kustomization/))


(Then, to deploy with gcloud builds)

Then, inside `deployment/oss-vdb-test/k8s/`

Manually modify `cloudbuild.yaml` to remove image building steps

Then run

```bash
gcloud beta builds submit . --project=<PROJECT_ID> --substitutions=COMMIT_SHA=<TAG>
```

This might time out if running the first time on a newly-created cluster.
It seems to trigger an auto-repair on the cluster. Running the command again
after the auto-repair finishes should work correctly.

## Quotas

It doesn't look like GCP Quota increase requests can be automated.

Things that have been manually set on `oss-vdb-test`:
- Compute Engine
  - CPUs => 1000
  - Local SSD => 100 TB
  - Pesistent Disk SSD => 50 TB

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

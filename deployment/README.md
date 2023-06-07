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

Terraform is automatically run on `oss-vdb-test` in `build-and-stage.yaml`


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

## Setting up additional pipelines

To setup additional pipelines, you need to create another directory, with a `clouddeploy.yaml` and `skaffold.yaml` file.
Easiest method would be to copy the structure in `gke-indexer/`

Then you need to add an entry to deploy-prod.yaml to do the promotion from staging to prod when releasing.

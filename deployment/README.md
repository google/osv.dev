# GCP Project Setup (WIP)

## API Domain Name

Due to [Terraform limitations](https://github.com/hashicorp/terraform-provider-google/issues/5528),
setting up the OSV API requires a custom domain.

For example, if you own `custom-domain.name` and want to serve the API at
`api.custom-domain.name`:

1. Verify domain ownership:

   Go to:

   `https://www.google.com/webmasters/verification/verification?authuser=0&domain=custom-domain.name`

   (Replace `custom-domain.name` in the URL with the actual domain you want to verify.)

   This link is usually generated when adding a domain mapping to a Cloud Run
   service. I’m not sure how to navigate to this page manually.

   Note: Adding a property from
   [Webmaster Central](https://www.google.com/webmasters/verification/home)
   adds it as a _site_, rather than as a _domain_.

2. Add a DNS CNAME record mapping:

   `api.custom-domain.name` → `ghs.googlehosted.com.`

## Terraform

Go to the relevant directory:

`/deployment/terraform/environments/<PROJECT_ID>`

Initialize Terraform:

```bash
terraform init
```

This only needs to be run once when setting up the Terraform directory, but it is
safe to run multiple times.

Plan and apply the required infrastructure:

terraform plan

Running plan shows what resources will be added, changed, or destroyed when
applying the configuration. It is not strictly required, but it is recommended
as a sanity check.

terraform apply

Running apply will output the same information as plan, and will prompt you
before applying changes.

Always review planned changes carefully (especially anything being destroyed).
In some cases, Terraform may unexpectedly destroy and recreate resources.

Use terraform plan and terraform apply to deploy any configuration changes.

Terraform is automatically run on oss-vdb-test in build-and-stage.yaml.

Setting up the Auto-scaler
There does not seem to be a good way to configure this through Terraform.

The following instructions are from
this GCP guide:

kubectl create clusterrolebinding cluster-admin-binding \
 --clusterrole cluster-admin --user "$(gcloud config get-value account)"

kubectl apply -f https://raw.githubusercontent.com/GoogleCloudPlatform/k8s-stackdriver/master/custom-metrics-stackdriver-adapter/deploy/production/adapter_new_resource_model.yaml

Build and deploy remote builds to oss-vdb-test
This is done automatically using Cloud Deploy, as part of build-and-stage.yaml,
which is triggered on pushes to the master branch.

The Cloud Deploy pipelines are configured in the oss-vdb project.

Manual builds / deployment
Manual builds are not officially supported, but are theoretically possible.

Building locally would require running docker build and docker push for the
relevant Dockerfiles, similar to what is done in build-and-stage.yaml.

Manual deployment without Cloud Deploy would require manually modifying the
Kubernetes or Cloud Run manifests in clouddeploy/ to fit your needs. You would
also need to replace the Cloud Deploy image names with actual container image
references.

Quotas
GCP quota increase requests do not appear to be automatable.

The following quota increases have been manually configured on oss-vdb-test:

Compute Engine

CPUs: 1000

Local SSD: 100 TB

Persistent Disk SSD: 50 TB

Setting up additional Cloud Deploy pipelines
To set up additional pipelines, create a new directory inside clouddeploy/
containing:

clouddeploy.yaml

skaffold.yaml

The required manifest files

The easiest method is to copy an existing pipeline structure, such as:

gke-indexer/ (GKE)

osv-api/ (Cloud Run)

You can also refer to the
Cloud Deploy quickstarts.

[!NOTE]
The targetId fields in the clouddeploy.yaml files must be unique across all pipelines.

To create the pipeline in GCP, run the following command inside the new Cloud
Deploy directory:

gcloud deploy apply --file=clouddeploy.yaml --region=us-central1 --project=oss-vdb

You must also add entries into:

build-and-stage.yaml
(to build/tag the required images and deploy to staging, including image name substitutions)

deploy-prod.yaml
(to promote staging to prod during releases)

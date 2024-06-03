# Terraform Cloud Builder Image
Used for running Terraform in Cloud Build. Contains the required `terraform` and `gcloud` executables.

Taken and modified from https://github.com/GoogleCloudPlatform/cloud-builders-community/tree/master/terraform

To build the builder, run
```
gcloud builds submit --project=oss-vdb --config=cloudbuild.yaml
```
The build should take about 10 minutes to complete.

Afterwards, can be used in Cloud Build as

```yaml
steps:
- name: gcr.io/oss-vdb/terraform
  args: ['init', '-no-color']
```

## Updating Terraform Version
`_TERRAFORM_VERSION` is defined in `cloudbuild.yaml`. Currently version 1.5.7

This can be modified in place, or set in Cloud Build CLI:
```
gcloud builds submit --project=oss-vdb --config=cloudbuild.yaml \
  --substitutions=_TERRAFORM_VERSION="1.5.7"
```

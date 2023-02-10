# Terraform Cloud Builder Image
Used for running Terraform in Cloud Build. Contains the required `terraform`, `gcloud`, and `jq` executables.

Taken and modified from https://github.com/GoogleCloudPlatform/cloud-builders-community/tree/master/terraform

To build the builder, run
```
gcloud builds submit --project=oss-vdb --config=cloudbuild.yaml
```

Afterwards, can be used in Cloud Build as

```yaml
steps:
- name: gcr.io/oss-vdb/terraform
  args: ['init', '-no-color']
```

## Updating Terraform Version
`_TERRAFORM_VERSION` and `_TERRAFORM_VERSION_SHA256SUM` are defined in `cloudbuild.yaml`. Currently version 1.3.7

This can be modified in place, or set in Cloud Build CLI:
```
gcloud builds submit --project=oss-vdb --config=cloudbuild.yaml \
  --substitutions=_TERRAFORM_VERSION="0.12.29",_TERRAFORM_VERSION_SHA256SUM="872245d9c6302b24dc0d98a1e010aef1e4ef60865a2d1f60102c8ad03e9d5a1d"
```

Checksums are listed on the [Terraform download page](https://developer.hashicorp.com/terraform/downloads) under 'Notes'. Checksum is for the `linux_amd64` version.
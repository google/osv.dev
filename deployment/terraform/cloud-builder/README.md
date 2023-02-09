# Terraform Cloud Builder Image
To run Terraform in Cloud Build.

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
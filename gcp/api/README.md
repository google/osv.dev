# API server

The API server runs on Cloud Run with Cloud Endpoints.

# API server updates (backend)

If the backend code (i.e. server.py) code is changed, follow these steps:

Pick a TAG to use for the build (base this on the date. e.g. date +"%Y%m%d")).

Note: You may need to run `gcloud auth configure-docker` the first time you run
this. See also
https://cloud.google.com/container-registry/docs/advanced-authentication#gcloud-helper

## Staging

```
./deploy_backend oss-vdb $(date +"%Y%m%d") osv-grpc-backend-staging
```

## Production

```
./deploy_backend oss-vdb $(date +"%Y%m%d") osv-grpc-backend
```

## oss-vdb-test Project
Building and deploying is now handled separately.

To build, inside project root folder:
```bash
docker build -t "gcr.io/oss-vdb-test/osv-server:<TAG>" -f gcp/api/Dockerfile .
docker push "gcr.io/oss-vdb-test/osv-server:<TAG>"
```

Use terraform to deploy - in `deployment/terraform/environments/oss-vdb-test/main.tf` modify the line
```
  api_backend_image_tag = "<TAG>"
```
Then use `terraform plan` and `terraform apply` to deploy.
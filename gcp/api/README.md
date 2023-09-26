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

Automatically built and deployed on pushes to master branch.

# Contributing:

## Writing tests
To speed up running tests:

1. `make run-api-server` at the root of this repository to start the test server.
2. `pipenv shell` in this directory
3. `python -m unittest integration_test.py` in this directory.

This avoids the need to start the test server (and waiting for it) every run.
# V1 API server

The API server runs on Cloud Run with Cloud Endpoints.

# GRPC and service configuration
Updates to the protobufs and service configurations require a few steps,
outlined below.

## Regenerate protobufs
Run from the root directory:
```sh
make build-protos
```
Or directly using `protoc`:
```sh
protoc \
    --include_imports \
    --include_source_info \
    --proto_path=proto \
    --proto_path=proto/v1 \
    --proto_path=osv \
    --proto_path=osv/osv-schema/proto \
    --descriptor_set_out=proto/v1/api_descriptor.pb \
    proto/v1/osv_service_v1.proto
```

## Deploy service proxy

Deployment is handled through terraform.

`api_descriptor.pb` is symlinked to inside `deployment/terraform/environments/oss-vdb[-test]/api/`,
Make any desired changes to `api_config.tftpl` in same folder.

`terraform plan` and `terraform apply` are automatically run on `oss-vdb-test` on pushes to the master branch.

For `oss-vdb`, terraform is run as part of the weekly release process.

## Deploy endpoints configuration for integration tests

The Cloud Endpoints service that is required for the unit tests to run is **not** automatically deployed (to allow for testing of proto changes). The testing service is `api-test.osv.dev` on the `oss-vdb` project.

The configuration for this service is located in this directory `api_config_test.yaml`. To deploy changes, use the following command:

```sh
gcloud endpoints services deploy api_descriptor.pb api_config_test.yaml --project=oss-vdb
```

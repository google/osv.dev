# V1 API server

The API server runs on Cloud Run with Cloud Endpoints.

# GRPC and service configuration
Updates to the protobufs and service configurations require a few steps,
outlined below.

## Regenerate protobufs
```
python3 -m grpc_tools.protoc \
    --include_imports \
    --include_source_info \
    --proto_path=googleapis \
    --proto_path=. \
    --proto_path=.. \
    --descriptor_set_out=api_descriptor.pb \
    --python_out=../. \
    --grpc_python_out=../ \
    osv_service_v1.proto
```

## Deploy service proxy
To deploy the service proxy,

### Test
```
../deploy_service_proxy api-test.osv.dev osv-grpc-v1-test api_config_test.yaml
```

### Staging
```
../deploy_service_proxy api-staging.osv.dev osv-grpc-v1-staging /path/to/api_config_staging.yaml
```

### Production

```
../deploy_service_proxy api.osv.dev osv-grpc-v1 /path/to/api_config.yaml
```

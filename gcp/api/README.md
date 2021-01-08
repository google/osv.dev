# API server

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
    --descriptor_set_out=api_descriptor.pb \
    --python_out=. \
    --grpc_python_out=. \
    osv_service.proto
```

## Rebuild service proxy for V0
To deploy the service proxy for the V0 (deprecated) API,

```
./deploy_service_proxy db.oss-fuzz.com osv-grpc /path/to/api_config.yaml
```

# API server updates (backend)
If the backend code (i.e. server.py) code is changed, follow these steps:

Pick a TAG (base this on the date. e.g. 20200101).

## Staging

```
sudo ./deploy_backend TAG osv-grpc-backend-staging
```

## Production

```
sudo ./deploy_backend TAG osv-grpc-backend
```

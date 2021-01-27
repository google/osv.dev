# API server

The API server runs on Cloud Run with Cloud Endpoints.

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

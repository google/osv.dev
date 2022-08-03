## Prerequisites

Install `protoc` for your platform:

https://grpc.io/docs/protoc-installation/

Install `clang` for your platform:

https://releases.llvm.org/download.html

In the root directory, update submodules:

```bash
git submodule update --init --recursive
```

Install `protoc-gen-openapiv2`:

```bash
go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2@latest
```

To install the protobuf service converter, run:

```bash
go mod download
```

# Documentation generation

API documentation is auto-generated from the service protobuf definitions. This
is done by converting the service definition to an OpenAPI 2/Swagger definition,
which is then rendered by [ReDoc](https://github.com/Redocly/redoc).

We also inject additional documentation via the various `*.md` files in this
directory.

Run:

```
python3 ./build.py
```

# Viewing changes locally

Go to the `gcp/appengine/docs` directory, and run:

```bash
$ python -m http.server
```

# Deployment

Docs are served from App Engine. To deploy them, change your working directory
to `gcp/appengine` and deploy.

```bash
./deploy.sh
```


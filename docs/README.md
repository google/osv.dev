# OpenAPI generation

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

## Generation

```
python3 ./build_swagger.py
```

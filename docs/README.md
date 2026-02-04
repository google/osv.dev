# OpenAPI Specification Generation

This guide outlines the protocol for generating OpenAPI (Swagger) documentation from Protobuf definitions. Ensure all environment dependencies are strictly met to maintain schema consistency.

---

## 🏗️ System Prerequisites

Before initiating the build process, you must install the following binary toolchains and language runtimes.

### 1. Core Toolchains

- **Protocol Buffers Compiler:** Install `protoc` via the [gRPC Installation Guide](https://grpc.io/docs/protoc-installation/).

- **C-Compiler:** Install `clang` from the [LLVM Hardware/Software releases](https://releases.llvm.org/download.html).

- **Go Runtime:** Ensure [Go](https://go.dev) is installed and your `$GOPATH/bin` is in your system's `PATH`.

### 2. Dependency Initialization

Synchronize the project's submodules to ensure the latest upstream Protobuf definitions are available:

```bash
git submodule update --init --recursive
```

3. Plugin & Library Installation
   Install the OpenAPI generation plugin for the gRPC Gateway and download required Go modules:

# Install the OpenAPI v2 generator plugin

go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2@latest

# Resolve and download Go dependencies for service conversion

go mod download

🚀 Generation Workflow :

Once the environment is configured, execute the build script to compile the Protobuf files into a static OpenAPI/Swagger specification.

# Run the Python build orchestrator

python3 ./build_swagger.py

Post-Generation Verification :

Output Directory: Verify the generated .json or .yaml files in the designated distribution folder.

Validation: It is recommended to validate the output using the Swagger Editor or a similar linting tool to ensure spec compliance.

🛠️ Troubleshooting

Missing Imports: If protoc fails, ensure the git submodule command was executed successfully.

Binary Conflicts: Ensure protoc-gen-openapiv2 is accessible by running which protoc-gen-openapiv2.

Would you like me to include a **GitHub Action** configuration to automatically **validate and deploy** these Swagger docs to a static site whenever you push a change?

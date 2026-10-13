Shim for the osv library in vanir to use the latest versions of the OSV proto

To regenerate the proto, run the following command:

```
poetry run python3 -m grpc_tools.protoc --python_out=. --proto_path=../../../../osv/osv-schema/proto vulnerability.proto
```
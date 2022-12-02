# Proof-of-concept code to leverage vulnfeeds for reasoning about C/C++ sources

This can be invoked as:

```shell
go run cpp/main.go \
  --nvd_json cve_jsons/nvdcve-1.1-2022.json \
```

Use `cmd/download-cves/main.go` for downloading the NVD JSON files

# Proof-of-concept code to leverage vulnfeeds for reasoning about C/C++ sources

This can be invoked as:

```shell
go run cpp/main.go \
  --nvd_json cve_jsons/nvdcve-1.1-2022.json \
  --debian_metadata_path debian_copyright/metadata.ftp-master.debian.org
```

Use `cmd/download-cves/main.go` for downloading the NVD JSON files and

```shell
wget \
  --directory debian_copyright
  --mirror \
  -A debian_copyright \
  -A index.html \
  https://metadata.ftp-master.debian.org/changelogs/main`
```

# Alpine Converter

This tool converts Alpine security database records to OSV format and uploads them to GCS.

## Usage

```bash
go run main.go [flags]
```

### Flags

- `-output-path`: Path to output general alpine affected package information (default: "alpine")
- `-output-bucket`: The GCS bucket to write to (default: "osv-test-cve-osv-conversion")
- `-workers`: Number of workers to process records (default: 64)
- `-upload-to-gcs`: If true, write to GCS bucket and instead of local disk (default: false)
- `-sync-deletions`: If false, do not delete files in bucket that are not local (default: false)

## Description

The tool performs the following steps:
1. Downloads the Alpine SecDB data from `https://secdb.alpinelinux.org/`.
2. Loads existing NVD CVEs data to extract human readable information like details and severity.
3. Generates OSV vulnerabilities by mapping Alpine security fixes to CVEs.
4. Uploads the results to GCS or writes them to the local filesystem.

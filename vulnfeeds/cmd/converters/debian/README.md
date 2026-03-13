# Debian Converter

This tool converts Debian Security Tracker information to OSV format.

## Usage

```bash
go run main.go [flags]
```

### Flags

- `-output-path`: Path to output OSV files (default: "debian-cve-osv").
- `-output-bucket`: The GCS bucket to write to (default: "debian-osv").
- `-workers`: Number of workers to process records (default: 64).
- `-upload-to-gcs`: If true, upload to GCS bucket instead of writing to local disk (default: false).
- `-sync-deletions`: If true, deletes files in the destination bucket that are not present in the source directory. This is useful for keeping the destination in sync with the source (default: false).

## Description

The tool performs the following steps:
1. Downloads the Debian Security Tracker data from `https://security-tracker.debian.org/tracker/data/json`.
2. Downloads Debian Distro Info data to map release names to version numbers.
3. Loads existing CVEs from `cve_jsons`.
4. Generates OSV vulnerabilities by mapping Debian security tracker entries to CVEs.
5. Uploads the results to GCS or writes them to the local filesystem.

# IDs Tool

This utility assigns IDs to OSV records in a directory. It ensures that IDs are unique and follow a specified prefix and year format.

It is predominately used by [PYSEC](https://github.com/pypa/advisory-database/blob/main/.github/workflows/automation.yaml) and [Malicious Packages](https://github.com/ossf/malicious-packages/blob/7b1ba332528dba6b0a2df23e9a43b384623c0251/.github/workflows/assign-osv-ids.yml#L35).

## Usage

```bash
go run main.go [flags]
```

### Flags

- `-prefix`: Vulnerability prefix (e.g., "PYSEC").
- `-dir`: Path to vulnerabilities.
- `-format`: Format of OSV reports in the repository. Must be "json" or "yaml" (default: "yaml").

## Description

The tool performs the following steps:
1. Walks the specified directory to find unassigned vulnerabilities (files starting with `PREFIX-0000-`).
2. Determines the maximum allocated ID for each year.
3. Assigns new IDs to unassigned vulnerabilities, incrementing the counter for the respective year.
4. Renames the files to match the new IDs.

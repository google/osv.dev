# IDs Tool

This utility assigns IDs to OSV records in a directory. It ensures that IDs are unique and follow a specified prefix and year format.

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

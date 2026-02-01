# Download CVEs

This tool downloads CVE data from the NVD 2.0 API data dumps.

## Usage

```bash
go run main.go [flags]
```

### Flags

- `-cve-path`: Where to download CVEs to (default: "cve_jsons").

## Description

The tool performs the following steps:
1. Downloads CVE JSON files for each year from 2002 to the current year.
2. Downloads "modified" and "recent" CVE feeds.
3. Saves the downloaded files to the specified directory.

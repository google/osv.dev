# CPE Dictionary Analysis Tool

This extracts likely repository URLs from the NVD CPE Dictionary.

See
https://storage.googleapis.com/cve-osv-conversion/cpe_repos/cpe_product_to_repo.json
for example output.

It can utilise Debian copyright metadata for additional inference. Populate that
metadata mirror with:

```bash
wget \
  --directory debian_copyright \
    --mirror \
    -A unstable_copyright \
    -A index.html \
    https://metadata.ftp-master.debian.org/changelogs/main
```

`cpe-repo-gen` analyzes the NVD CPE Dictionary for Open Source repository information.
It reads the NVD CPE Dictionary JSON files and outputs a JSON map of CPE products
to discovered repository URLs.

## Usage
```bash
go run main.go [flags]
```

### Flags

- `-cpe-dictionary-dir`: The path to the directory of NVD CPE Dictionary JSON files (default: "cve_json/nvdcpe-2.0-chunks"). See https://nvd.nist.gov/products/cpe
- `-debian-metadata-path`: The path to a directory containing a local mirror of Debian copyright metadata.
- `-output-dir`: The directory to output `cpe_product_to_repo.json` and `cpe_reference_description_frequency.csv` (default: ".").
- `-validate`: Perform remote validation of repositories and only include ones that validate successfully (default: true).
- `-verbose`: If true, output additional telemetry to stdout (default: false).
- `-gcp-logging-project`: GCP project ID to use for logging (default: "oss-vdb"). Set to the empty string to log to stdout

## Description

The tool performs the following steps:
1. Loads CPEs from the specified dictionary directory.
2. Analyzes the CPEs to find repository URLs in their references.
3. Optionally attempts to derive repository URLs from Debian copyright metadata.
4. Validates the discovered repositories by checking if they are reachable and have usable refs.
5. Outputs the product-to-repo map and a description frequency CSV.

# CPE Dictionary Analysis Tool

This extracts likely repository URLs from the NVD CPE Dictionary.

See
https://cve-osv-conversion.storage.googleapis.com/cpe_repos/cpe_product_to_repo.json
for example output.

It can utilise Debian copyright metadata for additional inference. Populate that
metadata mirror with:

```
wget \
  --directory debian_copyright \
    --mirror \
    -A unstable_copyright \
    -A index.html \
    https://metadata.ftp-master.debian.org/changelogs/main
```

```
cpe-repo-gen analyzes the NVD CPE Dictionary for Open Source repository information.
It reads the NVD CPE Dictionary XML file and outputs a JSON map of CPE products
to discovered repository URLs.

It can also output on stdout additional data about colliding CPE package names.

Usage:

    go run cmd/cpe-repo-gen/main.go [flags]

The flags are:

      --cpe_dictionary
        The path to the uncompressed NVD CPE Dictionary XML file, see https://nvd.nist.gov/products/cpe

      --debian_metadata_path
            The path to a directory containing a local mirror of Debian copyright metadata, see README.md

      --output_dir
            The directory to output cpe_product_to_repo.json and cpe_reference_description_frequency.csv in

      --gcp_logging_project
        The GCP project ID to utilise for Cloud Logging. Set to the empty string to log to stdout

      --verbose
        Output additional telemetry to stdout
```

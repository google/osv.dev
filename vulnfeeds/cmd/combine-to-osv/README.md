# combine-to-osv

This tool combines CVEs from CVE5 and NVD security advisories of the same ID into a single OSV record.
## Why

To address the generation of CVE records from multiple disparate sources (all requiring a common record prefix):

* CVEList, by [this code](../converters/cve/cve5)
* NVD, by [this code](../converters/cve/nvd-cve-osv)

## How

See [`run_combine_to_osv_convert.sh`](run_combine_to_osv_convert.sh):

* Reads from [`gs://cve-osv-conversion/nvd-osv`](https://storage.googleapis.com/cve-osv-conversion/index.html?prefix=nvd-osv/) and [`gs://cve-osv-conversion/cve5`](https://storage.googleapis.com/cve-osv-conversion/index.html?prefix=cve5/)
* Writes an OSV record to [`gs://cve-osv-conversion/osv-output`](https://storage.googleapis.com/cve-osv-conversion/index.html?prefix=osv-output/)
  * This is the import source for [`cve-osv`](https://github.com/google/osv.dev/blob/2c22e9534a521c6c6350275427f80e481065ca39/source.yaml#L96)
  * What gets written can be overridden by OSV records in [`gs://cve-osv-conversion/osv-output-overrides`](https://storage.googleapis.com/cve-osv-conversion/index.html?prefix=osv-output-overrides/)
## Operational matters

* Runs every hour (on the half hour) as a [Kubernetes CronJob](https://github.com/google/osv.dev/blob/master/deployment/clouddeploy/gke-workers/base/combine-to-osv.yaml)

## Usage

```bash
go run main.go [flags]
```

### Flags

- `-cve5-path`: Path to CVE5 OSV files (default: "cve5")
- `-nvd-path`: Path to NVD OSV files (default: "nvd")
- `-osv-output-path`: Local output path of combined OSV files, or GCS prefix if uploading (default: "osv-output")
- `-output-bucket`: The GCS bucket to write to (default: "osv-test-cve-osv-conversion")
- `-overrides-bucket`: The GCS bucket to read overrides from (default: "osv-test-cve-osv-conversion")
- `-upload-to-gcs`: If true, upload to GCS bucket instead of writing to local disk (default: false)
- `-workers`: Number of workers to process records (default: 64)
- `-sync-deletions`: If true, deletes files in the destination bucket that are not present in the source directory. This is useful for keeping the destination in sync with the source (default: false)

## Description

The tool performs the following steps:
1. Loads CVE5 OSVs from the specified path.
2. Loads NVD OSVs from the specified path.
3. Lists Debian and Alpine CVEs from GCS buckets to ensure mandatory CVEs are created.
4. Combines the loaded data into OSV records.
5. Uploads the results to GCS or writes them to the local filesystem.

### Overriding an OSV record

#### Situation

There's a generated OSV record that contains incorrect information and needs to be overriden (e.g. it is causing false positives)

Possible edits to consider making:

* remove or correct an incorrect `affected` entry
* add a `withdrawn` field

#### Considerations

This statically overrides the record generated, meaning any and all of the inputs for this record will be diregarded. The record will no longer change.

#### Procedure

1. `gcloud storage cp gs://cve-osv-conversion/osv-output/CVE-YYYY-NNNN.json`
2. manually edit the file
3. `gcloud storage cp gs://cve-osv-conversion/osv-output-overrides/CVE-YYYY-NNNN.json`

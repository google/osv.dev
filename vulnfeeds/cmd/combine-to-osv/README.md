# combine-to-osv

## What

Combine [`PackageInfo`](https://github.com/google/osv.dev/blob/2c22e9534a521c6c6350275427f80e481065ca39/vulnfeeds/vulns/vulns.go#L165-L171) file fragments into a single OSV record.

## Why

To address the generation of CVE records from multiple disparate sources (all requiring a common record prefix):

* Alpine, by [this code](../cmd/alpine)
* Debian, by [this code](../cmd/debian)
* the NVD, by [this code](../cmd/nvd-cve-osv)

## How

See [`run_combine_to_osv_convert.sh`](run_combine_to_osv_convert.sh):

* Reads from [`gs://cve-osv-conversion/parts`](https://storage.googleapis.com/cve-osv-conversion/index.html?prefix=parts/)
* Merges with CVE data from NVD (obtained from GCS mirror maintained by [`download-cves`](../download-cves/mirror_nvd.sh))
* Writes an OSV record to [`gs://cve-osv-conversion/osv-output`](https://storage.googleapis.com/cve-osv-conversion/index.html?prefix=osv-output/)
  * This is the import source for [`cve-osv`](https://github.com/google/osv.dev/blob/2c22e9534a521c6c6350275427f80e481065ca39/source.yaml#L96)
  * What gets written can be overridden by OSV records in [`gs://cve-osv-conversion/osv-output-overrides`](https://storage.googleapis.com/cve-osv-conversion/index.html?prefix=osv-output-overrides/)

## Operational matters

* Runs every 30 minutes as a [Kubernetes CronJob](https://github.com/google/osv.dev/blob/master/deployment/clouddeploy/gke-workers/base/combine-to-osv.yaml)

### Overriding an OSV record

#### Situation

There's a generated OSV record that contains incorrect information and needs to be overriden (e.g. it is causing false positives)

Possible edits to consider making:

* remove or correct an incorrect `affected` entry
* add a `withdrawn` field

#### Procedure

1. `gsutil cp gs://${OUTPUT_BUCKET}/osv-output/CVE-YYYY-NNNN.json`
2. manually edit the file
3. `gsutil cp gs://${INPUT_BUCKET/osv-output-overrides/CVE-YYYY-NNNN.json`

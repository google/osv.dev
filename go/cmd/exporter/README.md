# OSV Exporter

The exporter is responsible for creating many files in the OSV vulnerabilities bucket from the canonical protobuf vulnerability format.

The generated files are:
- `[ECOSYSTEM]/VULN-ID.json` - OSV JSON file for each vulnerability in each ecosystem
- `[ECOSYSTEM]/all.zip` - contains each OSV JSON file for that ecosystem
- `[ECOSYSTEM]/modified_id.csv` - contains the (modified, ID) of each vulnerability in the ecosystem directory
- `/ecosystems.txt` - a line-separated list of each exported ecosystem
- `/all.zip` - contains every OSV JSON file across all ecosytems
- `/modified_id.csv` - the (modified, [ECOSYSTEM]/ID) of every vulnerability across all ecosystem directories
- `GIT/osv_git.json` - a json array of every OSV vulnerability that has Vanir signatures.

## Running locally

To run the exporter locally, run the exporter from within the `go/cmd/exporter` directory, providing the GCS bucket containing the vulnerability protobufs via the `-osv_vulns_bucket` flag.

```sh
# Example
go run . -osv_vulns_bucket osv-test-vulnerabilities -uploadToGCS=false -bucket /tmp/osv-export
```

This will write the exported files to the `/tmp/osv-export` directory.

Note that running this takes quite a long time and uses a lot of memory.

### Flags

- `-bucket`: Output bucket or directory name. If `-uploadToGCS` is false, this is a local path; otherwise, it's a GCS bucket name.
- `-osv_vulns_bucket`: GCS bucket to read vulnerability protobufs from. Can also be set with the `OSV_VULNERABILITIES_BUCKET` environment variable.
- `-uploadToGCS`: If false, writes the output to a local directory specified by `-bucket` instead of a GCS bucket.
- `-num_workers`: The total number of concurrent workers to use for downloading from GCS and writing the output.

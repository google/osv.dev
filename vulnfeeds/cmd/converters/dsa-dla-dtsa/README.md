# Debian advisory converter

This converter will clone the following two repositories to create the DSA/DLA/DTSA OSV records:
- https://salsa.debian.org/security-tracker-team/security-tracker.git
- https://salsa.debian.org/webmaster-team/webwml.git

`git` also has to be installed and on the `PATH`, used to read modified dates of files.

## Run converter

### Usage:
```
go run main.go -o OUTPUT_DIR [-webwml WEBWML_REPO] [-security-tracker SECURITY_TRACKER_REPO] [-upload-to-gcs] [-output-bucket BUCKET_NAME] [-num-workers N]
```

#### Options:

`-o`:
Output directory to place the converted osv `.json` files. If `-upload-to-gcs` is set, this directory is used as a prefix for GCS paths.

`-webwml`:
(Optional) Path to the cloned webwml repository. If not provided, it will be cloned to a temporary directory.

`-security-tracker`:
(Optional) Path to the cloned security-tracker repository. If not provided, it will be cloned to a temporary directory.

`-upload-to-gcs`:
(Optional) If set, uploads the generated OSV records to GCS instead of writing them to the local disk.

`-output-bucket`:
(Optional) The GCS bucket to upload to (default: `debian-osv`).

`-num-workers`:
(Optional) Number of workers to use for GCS upload (default: 10).

### Example:
```
go run main.go -o ./output
```

This will automatically clone the necessary repositories, convert DSA, DLA, and DTSA advisories, and write the resulting JSON files to `./output/dsa`, `./output/dla`, and `./output/dtsa`.

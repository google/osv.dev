#!/bin/bash

## Converts Debian security tracker into general affected package information
## Then uploads the results to google cloud store.
##
## This script is intended to be the entrypoint of the docker image.
## with the working directory being the root of the repository

set -e

OSV_OUTPUT_PATH="debian-cve-osv"
INPUT_BUCKET="${INPUT_GCS_BUCKET:=osv-test-cve-osv-conversion}"
OUTPUT_BUCKET="${OUTPUT_GCS_BUCKET:=osv-test-debian-osv}"
CVE_OUTPUT="cve_jsons/"
WORKERS="${NUM_WORKERS:=256}"

echo "Setup initial directories ${OSV_OUTPUT_PATH}"
rm -rf $OSV_OUTPUT_PATH && mkdir -p $OSV_OUTPUT_PATH
rm -rf $CVE_OUTPUT && mkdir -p $CVE_OUTPUT

./debian -input-bucket "$INPUT_BUCKET" -output-bucket "$OUTPUT_BUCKET" -output-path "$OSV_OUTPUT_PATH" -cve-path "$CVE_OUTPUT" -workers "$WORKERS" -download-from-gcs -upload-to-gcs -sync-deletions
echo "Successfully converted and uploaded to cloud"

#!/bin/bash

## Converts alpine security advisory into general affected package information
## Then uploads the results to google cloud store.
##
## This script is intended to be the entrypoint of the docker image.
## with the working directory being the root of the repository

set -e

OSV_OUTPUT_PATH="alpine"
INPUT_BUCKET="${INPUT_GCS_BUCKET:=osv-test-cve-osv-conversion}"
OUTPUT_BUCKET="${OUTPUT_GCS_BUCKET:=osv-test-cve-osv-conversion}"
CVE_OUTPUT="cve_jsons/"
WORKERS="${NUM_WORKERS:=256}"


echo "Setup initial directories ${OSV_OUTPUT_PATH}"
rm -rf $OSV_OUTPUT_PATH && mkdir -p $OSV_OUTPUT_PATH
rm -rf $CVE_OUTPUT && mkdir -p $CVE_OUTPUT

echo "Begin syncing NVD data from GCS bucket ${INPUT_BUCKET}"
gcloud --no-user-output-enabled storage -q cp "gs://${INPUT_BUCKET}/nvd/*-????.json" "${CVE_OUTPUT}"
echo "Successfully synced from GCS bucket"

./alpine -output_bucket "$OUTPUT_BUCKET" -output_path "$OSV_OUTPUT_PATH" -num_workers "$WORKERS"
echo "Successfully converted and uploaded to cloud"
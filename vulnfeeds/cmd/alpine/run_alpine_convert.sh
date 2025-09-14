#!/bin/bash

## Converts alpine security advisory into general affected package information
## Then uploads the results to google cloud store.
##
## This script is intended to be the entrypoint of the docker image.
## with the working directory being the root of the repository

set -e

OSV_PARTS_OUTPUT="parts/alpine"
INPUT_BUCKET="${INPUT_GCS_BUCKET:=cve-osv-conversion}"
OUTPUT_BUCKET="${OUTPUT_GCS_BUCKET:=cve-osv-conversion}"
CVE_OUTPUT="cve_jsons/"

echo "Setup initial directories"
rm -rf $OSV_PARTS_OUTPUT && mkdir -p $OSV_PARTS_OUTPUT
rm -rf $CVE_OUTPUT && mkdir -p $CVE_OUTPUT

echo "Begin syncing NVD data from GCS bucket ${INPUT_BUCKET}"
gcloud --no-user-output-enabled storage -q cp "gs://${INPUT_BUCKET}/nvd/*-????.json" "${CVE_OUTPUT}"
echo "Successfully synced from GCS bucket"

./alpine-osv
echo "Begin Syncing with cloud"
gsutil -q -m rsync -c -d $OSV_PARTS_OUTPUT "gs://$OUTPUT_BUCKET/$OSV_PARTS_OUTPUT"
echo "Successfully synced with cloud"

#!/bin/bash

## Combines the general affected package information in google cloud store
## with CVE information from NVD database
##
## This script is intended to be the entrypoint of the docker image.
## with the working directory being the root of the repository

set -eu

INPUT_BUCKET="${INPUT_GCS_BUCKET:=cve-osv-conversion}"
OUTPUT_BUCKET="${OUTPUT_GCS_BUCKET:=cve-osv-conversion}"
OSV_PARTS_ROOT="parts/"
OSV_OUTPUT="osv_output/"
CVE_OUTPUT="cve_jsons/"
CVELIST="${CVELIST_PATH:=cvelistV5/}"

echo "Setup initial directories"
rm -rf $OSV_PARTS_ROOT && mkdir -p $OSV_PARTS_ROOT
rm -rf $OSV_OUTPUT && mkdir -p $OSV_OUTPUT
rm -rf $CVE_OUTPUT && mkdir -p $CVE_OUTPUT
[[ -n "$CVELIST" ]] && rm -rf $CVELIST

echo "Begin syncing from parts in GCS bucket ${INPUT_BUCKET}"
gcloud --no-user-output-enabled storage rsync "gs://${INPUT_BUCKET}/parts/" "$OSV_PARTS_ROOT" -r -q
echo "Successfully synced from GCS bucket"

echo "Begin syncing NVD data from GCS bucket ${INPUT_BUCKET}"
gcloud --no-user-output-enabled storage -q cp "gs://${INPUT_BUCKET}/nvd/*-????.json" "${CVE_OUTPUT}"
echo "Successfully synced from GCS bucket"

if [[ -n "$CVELIST" ]]; then
    echo "Clone CVE List"
    git clone --quiet https://github.com/CVEProject/cvelistV5
fi

echo "Run combine-to-osv"
./combine-to-osv -cvePath "$CVE_OUTPUT" -partsPath "$OSV_PARTS_ROOT" -osvOutputPath "$OSV_OUTPUT" -cveListPath "$CVELIST"

echo "Override"
gcloud --no-user-output-enabled storage rsync "gs://${INPUT_BUCKET}/osv-output-overrides/" $OSV_OUTPUT

echo "Begin syncing output to GCS bucket ${OUTPUT_BUCKET}"
gcloud --no-user-output-enabled storage rsync "$OSV_OUTPUT" "gs://${OUTPUT_BUCKET}/osv-output/" --checksums-only -c --delete-unmatched-destination-objects -q
echo "Successfully synced to GCS bucket"

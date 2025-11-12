#!/bin/bash

## Combines the general affected package information in google cloud store
## with CVE information from NVD database
##
## This script is intended to be the entrypoint of the docker image.
## with the working directory being the root of the repository

function __error_handing__() {
     local last_status_code=$1;
     local error_line_number=$2;
     echo 1>&2 "Error - exited with status $last_status_code at line $error_line_number";
}

trap  '__error_handing__ $? $LINENO' ERR

set -eu

INPUT_BUCKET="${INPUT_GCS_BUCKET:=cve-osv-conversion}"
OUTPUT_BUCKET="${OUTPUT_GCS_BUCKET:=cve-osv-conversion}"
NUM_WORKERS="${NUM_WORKERS:=64}"

OSV_OUTPUT="osv-output"
NVD_OSV_OUTPUT="nvd"
CVE5_OSV_OUTPUT="cve5" 

echo "Setup initial directories"
rm -rf $NVD_OSV_OUTPUT && mkdir -p $NVD_OSV_OUTPUT
rm -rf $OSV_OUTPUT && mkdir -p $OSV_OUTPUT
rm -rf $CVE5_OSV_OUTPUT && mkdir -p $CVE5_OSV_OUTPUT

echo "Begin syncing NVD data from GCS bucket ${INPUT_BUCKET}"
gcloud --no-user-output-enabled storage -q cp "gs://${INPUT_BUCKET}/nvd-osv/CVE-????-*.json" "${NVD_OSV_OUTPUT}"
echo "Successfully synced from GCS bucket"

echo "Begin syncing CVE5 data from GCS bucket ${INPUT_BUCKET}"
gcloud --no-user-output-enabled storage -q cp "gs://${INPUT_BUCKET}/cve5/CVE-????-*.json" "${CVE5_OSV_OUTPUT}"
echo "Successfully synced from GCS bucket"

echo "Run combine-to-osv"
./combine-to-osv \
    -cve5-path "$CVE5_OSV_OUTPUT" \
    -nvd-path "$NVD_OSV_OUTPUT" \
    -osv-output-path "$OSV_OUTPUT" \
    -upload-to-gcs \
    -output-bucket "${OUTPUT_BUCKET}" \
    -overrides-bucket "${INPUT_BUCKET}" \
    -workers "${NUM_WORKERS}"

echo "Successfully generated and uploaded OSV records."

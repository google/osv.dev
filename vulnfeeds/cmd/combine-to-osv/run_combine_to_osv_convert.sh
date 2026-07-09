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

INPUT_BUCKET="${INPUT_GCS_BUCKET:=osv-test-cve-osv-conversion}"
OUTPUT_BUCKET="${OUTPUT_GCS_BUCKET:=osv-test-cve-osv-conversion}"
NUM_WORKERS="${NUM_WORKERS:=64}"

OSV_OUTPUT="osv-output"

echo "Setup initial directories"
rm -rf $OSV_OUTPUT && mkdir -p $OSV_OUTPUT

echo "Run combine-to-osv"
./combine-to-osv \
    -cve5-path "gs://${INPUT_BUCKET}/cve5/" \
    -nvd-path "gs://${INPUT_BUCKET}/nvd-osv/" \
    -osv-output-path "$OSV_OUTPUT" \
    -upload-to-gcs \
    -output-bucket "${OUTPUT_BUCKET}" \
    -overrides-bucket "${INPUT_BUCKET}" \
    -workers "${NUM_WORKERS}"

echo "Successfully generated and uploaded OSV records."

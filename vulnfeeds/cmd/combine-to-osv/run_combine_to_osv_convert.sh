#!/bin/bash

## Combines the general affected package information in google cloud store
## with CVE information from NVD database
##
## This script is intended to be the entrypoint of the docker image.
## with the working directory being the root of the repository

set -e

INPUT_BUCKET="${INPUT_GCS_BUCKET:=cve-osv-conversion}"
OUTPUT_BUCKET="${OUTPUT_GCS_BUCKET:=cve-osv-conversion}"
OSV_PARTS_ROOT="parts/"
OSV_OUTPUT="osv_output/"
CVE_OUTPUT="cve_jsons/"

echo "Setup initial directories"
rm -rf $OSV_PARTS_ROOT && mkdir -p $OSV_PARTS_ROOT
rm -rf $OSV_OUTPUT && mkdir -p $OSV_OUTPUT
rm -rf $CVE_OUTPUT && mkdir -p $CVE_OUTPUT

echo "Begin syncing from parts in GCS bucket ${BUCKET}"
gsutil -q -m rsync -r "gs://${INPUT_BUCKET}/parts/" $OSV_PARTS_ROOT
echo "Successfully synced from GCS bucket"

echo "Run download-cves"
go run ./cmd/download-cves/ -cvePath $CVE_OUTPUT

echo "Run combine-to-osv"
go run ./cmd/combine-to-osv/ -cvePath $CVE_OUTPUT -partsPath $OSV_PARTS_ROOT -osvOutputPath $OSV_OUTPUT

echo "Begin syncing output to GCS bucket ${BUCKET}"
gsutil -q -m rsync $OSV_OUTPUT "gs://${OUTPUT_BUCKET}/osv-output/"
echo "Successfully synced to GCS bucket"

#!/bin/bash

## Combines the general affected package information in google cloud store
## with CVE information from NVD database
##
## This script is intended to be the entrypoint of the docker image.
## with the working directory being the root of the repository

set -e

OSV_PARTS_ROOT="parts/"
OSV_OUTPUT="osv_output/"
CVE_OUTPUT="cve_jsons/"

echo "Setup initial directories"
rm -rf $OSV_PARTS_ROOT && mkdir -p $OSV_PARTS_ROOT
rm -rf $OSV_OUTPUT && mkdir -p $OSV_OUTPUT
rm -rf $CVE_OUTPUT && mkdir -p $CVE_OUTPUT

echo "Begin syncing with cloud parts"
gsutil -q -m rsync -r "gs://cve-osv-conversion/parts/" $OSV_PARTS_ROOT
echo "Successfully synced with cloud parts"

echo "Run download-cves"
go run ./cmd/download-cves/ -cvePath $CVE_OUTPUT

echo "Run combine-to-osv"
go run ./cmd/combine-to-osv/ -cvePath $CVE_OUTPUT -partsPath $OSV_PARTS_ROOT -osvOutputPath $OSV_OUTPUT

echo "Begin syncing output with cloud"
gsutil -q -m rsync $OSV_OUTPUT "gs://cve-osv-conversion/osv-output/"
echo "Successfully synced with cloud"
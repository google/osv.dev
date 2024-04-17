#!/bin/bash

## Converts Debian security tracker into general affected package information
## Then uploads the results to google cloud store.
##
## This script is intended to be the entrypoint of the docker image.
## with the working directory being the root of the repository

set -e

OSV_PARTS_OUTPUT="parts/debian"
OUTPUT_BUCKET="${OUTPUT_GCS_BUCKET:=cve-osv-conversion}"

echo "Setup initial directories ${OSV_PARTS_OUTPUT}"
rm -rf $OSV_PARTS_OUTPUT && mkdir -p $OSV_PARTS_OUTPUT

./debian-osv
echo "Begin Syncing with cloud, GCS bucket: ${OUTPUT_BUCKET}"
gsutil -q -m rsync -c -d $OSV_PARTS_OUTPUT "gs://$OUTPUT_BUCKET/$OSV_PARTS_OUTPUT"
echo "Successfully synced with cloud"

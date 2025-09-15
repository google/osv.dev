#!/bin/bash

## Converts alpine security advisory into general affected package information
## Then uploads the results to google cloud store.
##
## This script is intended to be the entrypoint of the docker image.
## with the working directory being the root of the repository

set -e

OSV_PARTS_OUTPUT="parts/alpine"
OUTPUT_BUCKET="${OUTPUT_GCS_BUCKET:=cve-osv-conversion}"

echo "Setup initial directories"
rm -rf $OSV_PARTS_OUTPUT && mkdir -p $OSV_PARTS_OUTPUT

./alpine-osv
echo "Begin Syncing with cloud"
gcloud storage rsync $OSV_PARTS_OUTPUT "gs://$OUTPUT_BUCKET/$OSV_PARTS_OUTPUT" --delete-unmatched-destination-objects -q -c
echo "Successfully synced with cloud"

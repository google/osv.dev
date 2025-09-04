#!/bin/bash

## Converts Debian security tracker into general affected package information
## Then uploads the results to google cloud store.
##
## This script is intended to be the entrypoint of the docker image.
## with the working directory being the root of the repository

set -e

OSV_OUTPUT_PATH="/debian"
OUTPUT_BUCKET="${OUTPUT_GCS_BUCKET:=cve-osv-conversion}"

echo "Setup initial directories ${OSV_OUTPUT_PATH}"
rm -rf $OSV_OUTPUT_PATH && mkdir -p $OSV_OUTPUT_PATH

./debian-osv
echo "Begin Syncing with cloud, GCS bucket: ${OUTPUT_BUCKET}"
gsutil -q -m rsync -c -d $OSV_OUTPUT_PATH "gs://$OUTPUT_BUCKET/$OSV_OUTPUT_PATH"
echo "Successfully synced with cloud"

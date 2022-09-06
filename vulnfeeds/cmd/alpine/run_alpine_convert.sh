#!/bin/bash

## Converts alpine security advisory into general affected package information
## Then uploads the results to google cloud store.
##
## This script is intended to be the entrypoint of the docker image.
## with the working directory being the root of the repository

set -e

OSV_PARTS_OUTPUT="parts/alpine"

echo "Setup initial directories"
rm -rf $OSV_PARTS_OUTPUT && mkdir -p $OSV_PARTS_OUTPUT

go run ./cmd/alpine/
echo "Begin Syncing with cloud"
gsutil -q -m rsync -d $OSV_PARTS_OUTPUT "gs://cve-osv-conversion/parts/alpine"
echo "Successfully synced with cloud"
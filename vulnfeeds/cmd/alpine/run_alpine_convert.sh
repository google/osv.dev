#!/bin/bash

set -e

OSV_PARTS_OUTPUT="parts/alpine_output"

echo "Setup initial directories"
rm -rf $OSV_PARTS_OUTPUT && mkdir -p $OSV_PARTS_OUTPUT

go run ./cmd/alpine/
echo "Begin Syncing with cloud"
gsutil -q -m rsync -d $OSV_PARTS_OUTPUT "gs://cve-osv-conversion/parts/alpine"
echo "Successfully synced with cloud"
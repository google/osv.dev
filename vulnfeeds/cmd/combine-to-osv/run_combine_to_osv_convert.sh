#!/bin/bash -e

OSV_PARTS_ROOT=parts/
OSV_OUTPUT=osv_output/

echo "Setup initial directories"
rm -rf $OSV_PARTS_ROOT && mkdir -p $OSV_PARTS_ROOT
rm -rf $OSV_OUTPUT && mkdir -p $OSV_OUTPUT

echo "Begin syncing with cloud parts"
gsutil -q -m rsync -r gs://cve-osv-conversion/parts/ $OSV_PARTS_ROOT
echo "Successfully synced with cloud parts"

echo "Run combine-to-osv"
go run ./cmd/combine-to-osv/

echo "Begin syncing output with cloud"
gsutil -q -m rsync $OSV_OUTPUT gs://cve-osv-conversion/osv-output/
echo "Successfully synced with cloud"
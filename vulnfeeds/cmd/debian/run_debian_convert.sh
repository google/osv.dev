#!/bin/bash

## Converts Debian security tracker into general affected package information
## Then uploads the results to google cloud store.
##
## This script is intended to be the entrypoint of the docker image.
## with the working directory being the root of the repository

set -e

<<<<<<< HEAD
OSV_OUTPUT_PATH="/debian-cve-osv"
=======
OSV_OUTPUT_PATH="debian-cve-osv"
>>>>>>> upstream/master
INPUT_BUCKET="${INPUT_GCS_BUCKET:=cve-osv-conversion}"
OUTPUT_BUCKET="${OUTPUT_GCS_BUCKET:=debian-osv}"
CVE_OUTPUT="cve_jsons/"


echo "Setup initial directories ${OSV_OUTPUT_PATH}"
rm -rf $OSV_OUTPUT_PATH && mkdir -p $OSV_OUTPUT_PATH
rm -rf $CVE_OUTPUT && mkdir -p $CVE_OUTPUT

echo "Begin syncing NVD data from GCS bucket ${INPUT_BUCKET}"
gcloud --no-user-output-enabled storage -q cp "gs://${INPUT_BUCKET}/nvd/*-????.json" "${CVE_OUTPUT}"
echo "Successfully synced from GCS bucket"

./debian-osv
echo "Begin Syncing with cloud, GCS bucket: ${OUTPUT_BUCKET}"
gsutil -q -m rsync -c -d $OSV_OUTPUT_PATH "gs://$OUTPUT_BUCKET/$OSV_OUTPUT_PATH"
echo "Successfully synced with cloud"

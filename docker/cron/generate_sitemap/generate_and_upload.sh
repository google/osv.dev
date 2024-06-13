#!/bin/bash

set -e

SITEMAP_OUTPUT="sitemap_output/"
OUTPUT_BUCKET="${OUTPUT_GCS_BUCKET:=test-osv-dev-sitemap}"
BASE_URL_PATH="${BASE_URL:=https://test.osv.dev}"

echo "Begin sitemap generation for $BASE_URL_PATH"

generate_sitemap.py --base_url $BASE_URL_PATH

echo "Begin Syncing with cloud to $OUTPUT_BUCKET"

gsutil -m rsync -c -d $SITEMAP_OUTPUT "gs://$OUTPUT_BUCKET/"

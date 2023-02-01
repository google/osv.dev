#!/bin/bash -e

OUTPUT_BUCKET="${OUTPUT_GCS_BUCKET:=debian-osv}"

# Use the first_package_finder script to generate a first version cache.
pushd /src/debian_converter
echo "Finding first packages"
pipenv run python3 first_package_finder.py

echo "Syncing with cloud first_package_output"
gsutil -q -m rsync -d 'first_package_output' gs://$OUTPUT_BUCKET/first_package_output
echo "Successfully synced with cloud"

popd
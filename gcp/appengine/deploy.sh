#!/bin/bash -ex

pushd frontend3
npm run build:prod
popd

# Skip the '-e' editable library install as we copy in the "osv" library
# directly instead for deployment.
python3 -m pipenv requirements | grep -v '^-e '  > requirements.txt
gcloud app deploy app.yaml cron.yaml cron-service.yaml --project=oss-vdb

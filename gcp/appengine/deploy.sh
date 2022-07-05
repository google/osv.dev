#!/bin/bash -ex

pushd frontend3
npm run build:prod
popd

python3 -m pipenv lock -r > requirements.txt
gcloud app deploy app.yaml cron.yaml cron-service.yaml --project=oss-vdb

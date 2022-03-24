#!/bin/bash

pushd frontend
npm run build
popd

pushd frontend3
npm run build
popd

pipenv lock -r > requirements.txt
gcloud app deploy app.yaml cron.yaml cron-service.yaml --project=oss-vdb

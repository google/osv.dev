#!/bin/bash

pushd frontend
npm run build
popd

gcloud app deploy --project=oss-vdb

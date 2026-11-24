#!/bin/sh
set -e

gcloud functions deploy pypi \
  --gen2 \
  --region=us-central1 \
  --runtime=python313 \
  --source=. \
  --entry-point=publish \
  --trigger-topic=pypi-bridge \
  --service-account=pypi-publisher@oss-vdb.iam.gserviceaccount.com \
  --trigger-service-account=pypi-publisher@oss-vdb.iam.gserviceaccount.com \
  --project=oss-vdb \
  --max-instances=32 \
  --timeout=120

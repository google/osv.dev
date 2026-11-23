#!/bin/sh

poetry export -f requirements.txt -o requirements.txt
gcloud functions deploy pypi --runtime=python313 --trigger-topic=pypi-bridge --project=oss-vdb --entry-point=publish --service-account=pypi-publisher@oss-vdb.iam.gserviceaccount.com --max-instances=32 --timeout=120

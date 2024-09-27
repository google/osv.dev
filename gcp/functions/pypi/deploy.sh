#!/bin/sh

poetry export -f requirements.txt -o requirements.txt
gcloud functions deploy pypi --runtime=python311 --trigger-topic=pypi-bridge --project=oss-vdb --entry-point=publish --max-instances=32 --timeout=120

#!/bin/sh

# Poetry alternative
# poetry export --format=requirements.txt > requirements.txt
pipenv requirements > requirements.txt
gcloud functions deploy pypi --runtime=python39 --trigger-topic=pypi-bridge --project=oss-vdb --entry-point=publish --max-instances=32 --timeout=120

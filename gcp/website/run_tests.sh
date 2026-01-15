#!/bin/bash -ex

export GOOGLE_CLOUD_PROJECT=fake-project123

# Install dependencies only if not running in Cloud Build
if [ -z "$CLOUDBUILD" ]; then
  poetry sync
fi
poetry run python frontend_handlers_test.py

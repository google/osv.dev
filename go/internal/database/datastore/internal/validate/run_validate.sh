#!/bin/bash
# Install dependencies only if not running in Cloud Build
if [ -z "$CLOUDBUILD" ]; then
  poetry sync
fi
poetry run python validate.py
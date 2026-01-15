#!/bin/bash
# Install dependencies only if not running in Cloud Build
if [ -z "$BUILD_ID" ]; then
  poetry sync
fi
poetry run python validate.py
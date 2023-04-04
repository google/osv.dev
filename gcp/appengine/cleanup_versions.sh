#!/bin/bash

# Helper to clean up all but the most recent 5 versions of the default service
# in the given project

# Inspiration: https://stackoverflow.com/questions/34499875/how-to-automatically-delete-old-google-app-engine-version-instances

if [[ $# -lt 1 ]]; then
  echo "Usage: $(basename $0) project_id"
  exit 1
fi

PROJECT_ID="$1"

VERSIONS="$(gcloud \
  --project=$PROJECT_ID \
  app versions list --service=default \
  --format="value(version.id)" --sort-by="~version.createTime" \
  | tail -n +6)"

gcloud --project=$PROJECT_ID app versions delete --service=default --quiet $VERSIONS

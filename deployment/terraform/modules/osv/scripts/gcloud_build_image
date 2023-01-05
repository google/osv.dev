#!/bin/bash
# Copyright 2019 Google LLC

# This script will download the service config and build it into
# serverless docker image to be used for Cloud Run.
#
# gcloud SDK has to be installed and configured with:
#   gcloud config set project ${PROJECT}
#   gcloud auth login
#
# Following gcloud commands can be used to find out service name
#   gcloud endpoints services list
#   gcloud endpoints configs list --service=${SERVICE}
# Use the latest one for the CONFIG_ID
#
# The script will use the latest ESPv2 version by default.
# Use the -v option to pass in a custom version (example: -v 2.9).

# Fail on any error.
set -eo pipefail

# Default to the latest released ESPv2 version.
BASE_IMAGE_NAME="gcr.io/endpoints-release/endpoints-runtime-serverless"
ESP_TAG="2"
ZONE=""

function error_exit() {
  # ${BASH_SOURCE[1]} is the file name of the caller.
  echo "${BASH_SOURCE[1]}: line ${BASH_LINENO[0]}: ${1:-Unknown Error.} (exit ${2:-1})" 1>&2
  exit ${2:-1}
}

# To support Google Artifact Registry (GAR), the flag -g can be used to set
# IMAGE_REPOSITORY as following:
#   'LOCATION-docker.pkg.dev/PROJECT-ID/REPOSITORY'

while getopts :c:s:p:v:z:g:i: arg; do
  case ${arg} in
    c) CONFIG_ID="${OPTARG}";;
    s) SERVICE="${OPTARG}";;
    p) PROJECT="${OPTARG}";;
    v) ESP_TAG="${OPTARG}";;
    z) ZONE="${OPTARG}";;
    g) IMAGE_REPOSITORY="${OPTARG}";;
    i)
      BASE_IMAGE="${OPTARG}"
      ESP_FULL_VERSION="custom"
      ;;
    \?) error_exit "Unrecognized argument -${OPTARG}";;
  esac
done

[[ -n "${PROJECT}" ]] || error_exit "Missing required PROJECT"
[[ -n "${SERVICE}" ]] || error_exit "Missing required SERVICE"
[[ -n "${CONFIG_ID}" ]] || error_exit "Missing required CONFIG_ID"

# If user did not pass in custom image, then form the fully-qualified base image.
if [ -z "${BASE_IMAGE}" ]; then
  BASE_IMAGE="${BASE_IMAGE_NAME}:${ESP_TAG}"
fi;
echo "Using base image: ${BASE_IMAGE}"

# If IMAGE_REPOSITORY is not set, it is to support container registry format:
#   'gcr.io/PROJECT-ID' or 'us.gcr.io/PROJECT-ID'
if [ -z "${IMAGE_REPOSITORY}" ]; then
  IMAGE_REPOSITORY="gcr.io/${PROJECT}"
  if [ -n "${ZONE}" ]; then
    IMAGE_REPOSITORY="${ZONE}.${IMAGE_REPOSITORY}"
  fi
fi

# If user did not pass in a custom image, then determine the ESP version.
if [ -z "${ESP_FULL_VERSION}" ]; then
  echo "Determining fully-qualified ESP version for tag: ${ESP_TAG}"

  ALL_TAGS=$(gcloud container images list-tags "${BASE_IMAGE_NAME}" \
      --filter="tags~^${ESP_TAG}$" \
      --format="value(tags)")
  IFS=',' read -ra TAGS_ARRAY <<< "${ALL_TAGS}"

  if [ ${#TAGS_ARRAY[@]} -eq 0 ]; then
    error_exit "Did not find ESP version: ${ESP_TAG}"
  fi;

  # Find the tag with the longest length.
  ESP_FULL_VERSION=""
  for tag in "${TAGS_ARRAY[@]}"; do
     if [ ${#tag} -gt ${#ESP_FULL_VERSION} ]; then
        ESP_FULL_VERSION=${tag}
     fi
  done
fi
echo "Building image for ESP version: ${ESP_FULL_VERSION}"

tempdir="$(mktemp -d /tmp/docker.XXXX)"
cd "${tempdir}"

# Be careful about exposing the access token.
access_token="$(gcloud auth print-access-token)"
curl --fail -o "service.json" -H @- \
  "https://servicemanagement.googleapis.com/v1/services/${SERVICE}/configs/${CONFIG_ID}?view=FULL" <<EOF || error_exit "Failed to download service config"
Authorization: Bearer ${access_token}
EOF

(
set -x

cat <<EOF > Dockerfile
FROM ${BASE_IMAGE}

USER root
ENV ENDPOINTS_SERVICE_PATH /etc/endpoints/service.json
COPY service.json \${ENDPOINTS_SERVICE_PATH}
RUN chown -R envoy:envoy \${ENDPOINTS_SERVICE_PATH} && chmod -R 755 \${ENDPOINTS_SERVICE_PATH}
USER envoy

ENTRYPOINT ["/env_start_proxy.py"]
EOF

NEW_IMAGE="${IMAGE_REPOSITORY}/endpoints-runtime-serverless:${ESP_FULL_VERSION}-${SERVICE}-${CONFIG_ID}"
gcloud builds submit --tag "${NEW_IMAGE}" . --project="${PROJECT}"
)

# Delete the temporary directory we created earlier.
# Move back to the previous directory with an echo.
rm -r "${PWD}"
cd ~-

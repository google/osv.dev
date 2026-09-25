#!/bin/bash
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euo pipefail

echo "Commencing GHSA repository-specific advisory conversion run"

NUM_WORKERS="${NUM_WORKERS:=8}"
OUTPUT_BUCKET="${OUTPUT_BUCKET:=osv-test-ghsa-repo-conversion}"
REPOS_FILE="${REPOS_FILE:=}"
REPOS_GCS_PATH="${REPOS_GCS_PATH:=}"
LOCAL_OUT_DIR="${LOCAL_OUT_DIR:=output}"
GCS_PREFIX="${GCS_PREFIX:=ghsa-repo-osv}"
GOOGLE_CLOUD_PROJECT="${GOOGLE_CLOUD_PROJECT:=}"
DATASTORE_JOB_ID="${DATASTORE_JOB_ID:=repository_ghsa_last_run}"
GITHUB_TOKEN="${GITHUB_TOKEN:=}"

ARGS=(
  "--workers=${NUM_WORKERS}"
  "--out-dir=${LOCAL_OUT_DIR}"
  "--output-bucket=${OUTPUT_BUCKET}"
  "--gcs-prefix=${GCS_PREFIX}"
  "--upload-to-gcs=true"
)

if [[ -n "${REPOS_GCS_PATH}" ]]; then
  ARGS+=("--repos-gcs-path=${REPOS_GCS_PATH}")
elif [[ -n "${REPOS_FILE}" ]]; then
  ARGS+=("--repos-file=${REPOS_FILE}")
fi

if [[ -n "${GOOGLE_CLOUD_PROJECT}" ]]; then
  ARGS+=("--datastore-project=${GOOGLE_CLOUD_PROJECT}")
  ARGS+=("--datastore-job-id=${DATASTORE_JOB_ID}")
  ARGS+=("--save-last-run=true")
fi

if [[ -n "${GITHUB_TOKEN}" ]]; then
  ARGS+=("--github-token=${GITHUB_TOKEN}")
fi

echo "Running repository-ghsa with arguments: ${ARGS[*]}"
exec /root/repository-ghsa "${ARGS[@]}" "$@"

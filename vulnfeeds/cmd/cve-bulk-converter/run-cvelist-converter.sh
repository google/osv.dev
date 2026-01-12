#!/bin/bash

# Copyright 2025 Google LLC
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

# This script executes a run of the CVEList to OSV conversion code.
# It operates over the latest available CVEList git clone and only the subset of years
# and CNAs specified.
# It assumes it is running in a Docker container

function __error_handing__() {
     local last_status_code=$1;
     local error_line_number=$2;
     echo 1>&2 "Error - exited with status $last_status_code at line $error_line_number";
}

trap  '__error_handing__ $? $LINENO' ERR

set -e
set -u


echo "Commencing cvelist conversion run"
NUM_WORKERS="${NUM_WORKERS:=30}"

OUTPUT_BUCKET="${OUTPUT_BUCKET:=osv-test-cve-osv-conversion}"
OSV_OUTPUT_PATH="cve5"
OSV_OUTPUT_GCS_PATH="gs://${OUTPUT_BUCKET}/${OSV_OUTPUT_PATH}"
CVELIST="${CVELIST_PATH:=cvelistV5/}"
LOCAL_OUT_DIR="${LOCAL_OUT_DIR:=cvelist2osv}"

mkdir -p "${LOCAL_OUT_DIR}/gcs_stage"
[[ -n "$CVELIST" ]] && rm -rf $CVELIST

# Clone CVEList5 repository
if [[ -n "$CVELIST" ]]; then
    echo "Clone CVEList"
    git clone https://github.com/CVEProject/cvelistV5 --depth=1
    echo "Finished cloning CVEList"
fi

# Convert CVEList records to OSV.
echo "Commence CVEList bulk conversion run"
./cve-bulk-converter \
 --start-year="2022" \
 --out-dir="${LOCAL_OUT_DIR}/${OSV_OUTPUT_PATH}" \
 --workers="${NUM_WORKERS}"

# Copy results to staging area.
echo "Copying CVEList records successfully converted to OSV to aggregated staging"
find "${LOCAL_OUT_DIR}/${OSV_OUTPUT_PATH}" -type f -name \*.json \
  -exec cp '{}' "${LOCAL_OUT_DIR}/gcs_stage/" \;

# Copy (and remove any missing) results to GCS bucket, with some sanity
# checking.
objs_present=$(gsutil ls "${OSV_OUTPUT_GCS_PATH}" | wc -l)
objs_deleted=$(gsutil -m rsync -c -n -d "${LOCAL_OUT_DIR}/gcs_stage" "${OSV_OUTPUT_GCS_PATH}" 2>&1 | grep "Would remove" | wc -l)

threshold=$(echo "scale=2; ${objs_present} * (${SAFETY_THRESHOLD_PCT:-2} / 100)" | bc)

# # Bash can't deal with floats
if (( $(echo "${objs_deleted} > ${threshold}" | bc -l) )); then
  echo "Aborting. Unexpectedly high (${objs_deleted}) number of CVE records would be deleted!" >> /dev/stderr
  gsutil -m rsync -c -n -d "${LOCAL_OUT_DIR}/gcs_stage" "${OSV_OUTPUT_GCS_PATH}" 2>&1 | grep "Would remove" >> /dev/stderr
  exit 1
fi

echo "Copying CVEList records successfully converted to GCS bucket"
gsutil -q -m rsync -c -d "${LOCAL_OUT_DIR}/gcs_stage" "${OSV_OUTPUT_GCS_PATH}"

echo "Conversion run complete"

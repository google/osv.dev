#!/bin/bash

# Copyright 2023 Google LLC
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

# This script creates year-based JSON dumps of the NVD, using the NVD 2.0 API.
# They are conceptually similar to the legacy JSON dumps that have been
# discontinued by the NVD.
# They are saved to GCS for use by combine-to-osv and the NVD to OSV conversion.

function __error_handing__() {
     local last_status_code=$1;
     local error_line_number=$2;
     echo 1>&2 "Error - exited with status $last_status_code at line $error_line_number";
}

trap  '__error_handing__ $? $LINENO' ERR

set -e

echo "Downloading the entire NVD"
mkdir -p "${WORK_DIR}/nvd"
./download-cves --cvePath "${WORK_DIR}/nvd"

echo "Copying files to GCS bucket"
gcloud config set storage/parallel_composite_upload_enabled True
gcloud --no-user-output-enabled storage rsync "${WORK_DIR}/nvd/" "gs://${BUCKET}/nvd/" --checksums-only -c --delete-unmatched-destination-objects -q

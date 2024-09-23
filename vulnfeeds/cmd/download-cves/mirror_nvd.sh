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

set -e

echo "Downloading the entire NVD"
mkdir -p "${WORK_DIR}/nvd"
APIKEY="$(gcloud --project "$GOOGLE_CLOUD_PROJECT" secrets versions access latest --secret=nvd-api --format='get(payload.data)' | base64 -d)"
/usr/local/bin/download-cves --api_key "$APIKEY" --cvePath "${WORK_DIR}/nvd"

echo "Splitting monolithic file into years"
for (( YEAR = 2002 ; YEAR <= $(date +%Y) ; YEAR++ ))
do
  cat "${WORK_DIR}/nvd/nvdcve-2.0.json" \
    | jq \
      --arg year $YEAR \
      'def count_matching_cves:
          reduce .vulnerabilities[] as $v (0;
          if $v.cve?.id? | startswith("CVE-" + $year + "-") then . + 1 else . end
        );

        {
        "resultsPerPage": count_matching_cves,
        "startIndex": 0,
        "totalResults": count_matching_cves,
        "format": .format,
        "version": .version,
        "timestamp": .timestamp,
        "vulnerabilities": .vulnerabilities | map(select(.cve?.id? | startswith("CVE-" + $year + "-")))
       }' > "${WORK_DIR}/nvd/nvdcve-2.0-${YEAR}.json" &
done

wait

echo "Copying files to GCS bucket"
gcloud config set storage/parallel_composite_upload_enabled True
gcloud --no-user-output-enabled storage rsync "${WORK_DIR}/nvd/" "gs://${BUCKET}/nvd/" --checksums-only -c --delete-unmatched-destination-objects -q

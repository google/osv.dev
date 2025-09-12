#!/bin/bash

# Copyright 2021 Google LLC
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
#
#
# Maintain a regularly generated CPE to repo mapping in a GCS bucket.
#
# Inputs:
# * A local work directory
# * A GCS bucket name + path for Debian copyright metadata
# * A GCS bucket name + path for the resulting map file

# Setting BE_VERBOSE to an empty string or null value suppresses silencing of
# commands

mkdir -p "${WORK_DIR}" || true

CPE_JSON_DIR="${WORK_DIR}/cpe_json"
mkdir -p "${CPE_JSON_DIR}" || true

curl ${BE_VERBOSE="-q"} \
  https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.zip \
  -o "${WORK_DIR}/cpe.zip"

unzip -o "${WORK_DIR}/cpe.zip" -d "${CPE_JSON_DIR}"

MAYBE_USE_DEBIAN_COPYRIGHT_METADATA=""
if [[ -n "${DEBIAN_COPYRIGHT_GCS_PATH}" ]]; then
  gcloud storage cp "${DEBIAN_COPYRIGHT_GCS_PATH}" "${WORK_DIR}" ${BE_VERBOSE="-q"}
  tar -C "${WORK_DIR}" -xf "${WORK_DIR}/$(basename ${DEBIAN_COPYRIGHT_GCS_PATH})"
  MAYBE_USE_DEBIAN_COPYRIGHT_METADATA="--debian_metadata_path ${WORK_DIR}/metadata.ftp-master.debian.org"
fi

./cpe-repo-gen \
  --cpe_dictionary_dir="${CPE_JSON_DIR}/nvdcpe-2.0-chunks" \
  ${MAYBE_USE_DEBIAN_COPYRIGHT_METADATA} \
  --output_dir="${WORK_DIR}"


gcloud storage cp "${WORK_DIR}/cpe_product_to_repo.json" "${CPEREPO_GCS_PATH}" ${BE_VERBOSE="-q"}

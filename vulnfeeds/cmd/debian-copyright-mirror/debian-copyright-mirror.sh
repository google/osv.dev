#!/bin/bash
#
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
# Maintain a GCS bucket mirror of Debian's copyright files
#
#
#
# Inputs:
# * A local work directory
# * GCS bucket name + path to tarball
#

# Setting BE_VERBOSE to an empty string or null value suppresses silencing of
# commands

mkdir -p "${WORK_DIR}" || true

if gsutil --quiet stat "${GCS_PATH}"; then
  gsutil ${BE_VERBOSE="--quiet"} cp "${GCS_PATH}" "${WORK_DIR}"
  tar -C "${WORK_DIR}" -xf "${WORK_DIR}/$(basename ${GCS_PATH})"
fi

wget \
  ${BE_VERBOSE="--quiet"} \
  --directory "${WORK_DIR}" \
  --mirror \
  --accept unstable_copyright \
  --accept index.html \
  https://metadata.ftp-master.debian.org/changelogs/main

tar -C "${WORK_DIR}" -cf "${WORK_DIR}/$(basename ${GCS_PATH})" .

gsutil ${BE_VERBOSE="--quiet"} cp "${WORK_DIR}/$(basename ${GCS_PATH})" "${GCS_PATH}"

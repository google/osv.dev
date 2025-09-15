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

python debian-copyright-mirror.py "${WORK_DIR}/metadata.ftp-master.debian.org/changelogs/"

tar -C "${WORK_DIR}" -cf "${WORK_DIR}/$(basename ${GCS_PATH})" .

gcloud storage cp "${WORK_DIR}/$(basename ${GCS_PATH})" "${GCS_PATH}" ${BE_VERBOSE="-q"}

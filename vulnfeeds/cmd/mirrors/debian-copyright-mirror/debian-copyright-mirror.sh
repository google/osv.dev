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
# Inputs:
# * A local work directory ($WORK_DIR)
# * GCS bucket name + path to tarball ($GCS_PATH)
#

mkdir -p "${WORK_DIR}" || true

debian-copyright-mirror \
  -work-dir "${WORK_DIR}/metadata.ftp-master.debian.org/changelogs/" \
  -gcs-path "${GCS_PATH}"

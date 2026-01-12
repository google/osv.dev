#!/bin/bash -x
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

if [ $# -lt 1 ]; then
  echo "Usage: $0 /path/to/credential.json"
  exit 1
fi

export GOOGLE_CLOUD_PROJECT=oss-vdb-test OSV_VULNERABILITIES_BUCKET=osv-test-vulnerabilities

# Try to start docker if not running (mostly for CI)
service docker start || true

set -e

poetry install
poetry run python run_apitester.py "$1"

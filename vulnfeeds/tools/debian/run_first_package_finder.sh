#!/bin/bash -e

# Copyright 2022 OSV Schema Authors
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

OUTPUT_BUCKET="${OUTPUT_GCS_BUCKET:=debian-osv}"

# Set working dir to script dir
cd "$(dirname "$0")"

# Use the first_package_finder script to generate a first version cache.
pushd ./debian_converter
echo "Finding first packages"
poetry run python3 first_package_finder.py

echo "Syncing with cloud first_package_output ${OUTPUT_BUCKET}"
gsutil -q -m rsync -c -d 'first_package_output' "gs://${OUTPUT_BUCKET}/first_package_output"
echo "Successfully synced with cloud"

popd
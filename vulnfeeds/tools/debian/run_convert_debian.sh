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

DSA_PATH=security-tracker
WEBWML_PATH=webwml
OSV_DSA_OUT=/tmp/osv/dsa
OSV_DLA_OUT=/tmp/osv/dla
OSV_DTSA_OUT=/tmp/osv/dtsa
OUTPUT_BUCKET="${OUTPUT_GCS_BUCKET:=debian-osv}"

# Set working dir to script dir
cd "$(dirname "$0")"

echo "Setup initial directories"
rm -rf $OSV_DSA_OUT && mkdir -p $OSV_DSA_OUT
rm -rf $OSV_DLA_OUT && mkdir -p $OSV_DLA_OUT
rm -rf $OSV_DTSA_OUT && mkdir -p $OSV_DTSA_OUT

# Use the OSV schema's reference Debian converter.
pushd ./debian_converter
echo "Cloning security tracker"
git clone --quiet https://salsa.debian.org/security-tracker-team/security-tracker.git --depth=1
echo "Cloning webwml"
git clone --quiet https://salsa.debian.org/webmaster-team/webwml.git
echo "Converting DSAs"
poetry run python3 convert_debian.py --adv_type=DSA -o $OSV_DSA_OUT $WEBWML_PATH $DSA_PATH
echo "Converting DLAs"
poetry run python3 convert_debian.py --adv_type=DLA -o $OSV_DLA_OUT $WEBWML_PATH $DSA_PATH
echo "Converting DTSAs"
poetry run python3 convert_debian.py --adv_type=DTSA -o $OSV_DTSA_OUT $WEBWML_PATH $DSA_PATH
popd

echo "Begin Syncing with cloud"
gsutil -m rsync -c -d $OSV_DSA_OUT gs://$OUTPUT_BUCKET/dsa-osv
gsutil -m rsync -c -d "$OSV_DLA_OUT" "gs://${OUTPUT_BUCKET}/dla-osv"
gsutil -m rsync -c -d "$OSV_DTSA_OUT" "gs://${OUTPUT_BUCKET}/dtsa-osv"
echo "Successfully synced with cloud"
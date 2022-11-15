#!/bin/sh
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

if [ $# -lt 1 ]; then
  echo "Usage: $0 /path/to/service_account.json"
  exit 1
fi

rm -rf osv
cp -r ../../osv .

pipenv requirements > requirements.txt
virtualenv ENV
. ENV/bin/activate
pip install -r requirements.txt
service docker start

export GOOGLE_CLOUD_PROJECT=oss-vdb
export GOOGLE_APPLICATION_CREDENTIALS="$1"
python integration_tests.py "$1"

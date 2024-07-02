#!/bin/bash -x
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
  echo "Usage: $0 /path/to/credential.json"
  exit 1
fi

export GOOGLE_CLOUD_PROJECT=oss-vdb
service docker start

if [ "$USE_POETRY" == "true" ]
then
  # Set -e later as service docker start should be able to successfully fail
  set -e
  poetry install
  poetry run python server_test.py
  poetry run python integration_tests.py "$1"
  exit 0
fi

python3 -m pipenv sync

export PIPENV_IGNORE_VIRTUALENVS=1
python3 -m pipenv run python server_test.py
python3 -m pipenv run python integration_tests.py "$1"

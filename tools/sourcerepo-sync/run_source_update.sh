#!/bin/bash -x
# Copyright 2024 Google LLC
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

export PIPENV_IGNORE_VIRTUALENVS=1
pipenv sync

pipenv run python source_sync.py --kind SourceRepository --project oss-vdb --file ../../source.yaml --no-dry-run --verbose
pipenv run python source_sync.py --kind SourceRepository --project oss-vdb-test --file ../../source_test.yaml --no-dry-run --verbose
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

script_dir=$(dirname "$0")
IN_SCOPE_FILES="$(git ls-files | grep '\.py$' | grep -v -E '(_pb2|third_party)')"

lint_findings=""
if ! echo "$IN_SCOPE_FILES" | xargs pylint --rcfile="$script_dir/../.pylintrc"; then
  lint_findings="lint_findings"
fi

format_findings=""
if ! echo "$IN_SCOPE_FILES" | xargs yapf -d --style "$script_dir/../.style.yapf"; then
  format_findings="format_findings"
fi

if [ $lint_findings ] || [ $format_findings ]; then
  echo "Please fix the above findings"
  exit 1
fi

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
IN_SCOPE_PYTHON_FILES="$(git ls-files | grep '\.py$' | grep -v -E '(_pb2|third_party)')"
# Explicitly excluding the docs directory due to
# tools.go:4:2: import "github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2" is a program,not an importable package
# tools.go:5:2: import "google.golang.org/grpc/cmd/protoc-gen-go-grpc" is a program, not an importable package
# tools.go:6:2: import "google.golang.org/protobuf/cmd/protoc-gen-go" is a program, not an importable package
# See also https://github.com/google/osv.dev/issues/573
IN_SCOPE_GO_MODULES="$(git ls-files | fgrep go.mod | fgrep -v docs | xargs dirname)"

python_lint_findings=""
if ! echo "$IN_SCOPE_PYTHON_FILES" | xargs pylint --rcfile="$script_dir/../.pylintrc"; then
  python_lint_findings="python_lint_findings"
fi

python_format_findings=""
if ! echo "$IN_SCOPE_PYTHON_FILES" | xargs yapf -d --style "$script_dir/../.style.yapf"; then
  python_format_findings="python_format_findings"
fi

go_vet_findings=""
for module_dir in $IN_SCOPE_GO_MODULES; do
  cd "$module_dir"
  if ! go vet ./...; then
    go_vet_findings="go_vet_findings"
  fi
  cd - > /dev/null
done

if [ $python_lint_findings ] || [ $python_format_findings ] || [ $go_vet_findings ]; then
  echo "Please fix the above findings"
  exit 1
fi

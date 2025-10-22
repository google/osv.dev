#!/bin/sh
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

set -e

python -m grpc_tools.protoc \
  --include_imports \
  --include_source_info \
  --proto_path=googleapis \
  --proto_path=. \
  --proto_path=v1 \
  --proto_path=../../osv \
  --proto_path=../../osv/osv-schema/proto \
  --descriptor_set_out=api_descriptor.pb \
  --python_out=. \
  --grpc_python_out=. \
  --mypy_out=. \
  --mypy_grpc_out=. \
  vulnerability.proto importfinding.proto osv_service_v1.proto

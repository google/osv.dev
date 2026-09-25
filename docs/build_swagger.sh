#!/usr/bin/env bash
# Copyright 2026 Google LLC
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

set -euo pipefail

DOCS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$DOCS_DIR")"
TARGET_FILE="$DOCS_DIR/osv_service_v1.swagger.json"
GENERATED_FILE="$DOCS_DIR/v1/osv_service_v1.swagger.json"

protoc \
  -I "$ROOT_DIR/proto" \
  -I "$ROOT_DIR/proto/v1" \
  -I "$ROOT_DIR/osv" \
  -I "$ROOT_DIR/osv/osv-schema/proto" \
  --openapiv2_out="$DOCS_DIR" \
  --openapiv2_opt=logtostderr=true \
  "$ROOT_DIR/proto/v1/osv_service_v1.proto"

# Set OpenAPI host and metadata
jq '.host = "api.osv.dev" | .info.title = "OSV" | .info.version = "1.0"' "$GENERATED_FILE" > "$TARGET_FILE"

rm -f "$GENERATED_FILE"
rmdir "$DOCS_DIR/v1" 2>/dev/null || true

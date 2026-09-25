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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"

# If OSV_API_BASE_URL is explicitly set, run directly against that endpoint.
if [ -n "${OSV_API_BASE_URL:-}" ]; then
  echo "Running apitester against $OSV_API_BASE_URL..."
  cd "$SCRIPT_DIR"
  go test ./...
  exit 0
fi

# Check for GCP Application Default Credentials
CRED_PATH="${HOME}/.config/gcloud/application_default_credentials.json"
if [ ! -f "$CRED_PATH" ]; then
  echo "GCP Application Default Credentials not found at $CRED_PATH."
  echo "Please run 'gcloud auth application-default login' or set OSV_API_BASE_URL (e.g. OSV_API_BASE_URL=api.test.osv.dev)"
  exit 1
fi

# Ensure the local ESPv2 Docker image is built
docker inspect osv/esp:latest >/dev/null 2>&1 || docker build -f "$ROOT_DIR/docker/esp/Dockerfile" -t osv/esp:latest "$ROOT_DIR/docker/esp"

# Build api-devserver
echo "Building api-devserver..."
cd "$ROOT_DIR/go"
go build -o ./api-devserver ./cmd/api-devserver

# Launch api-devserver against the staging/test dataset in the background
echo "Starting local API test server..."
GOOGLE_CLOUD_PROJECT="${GOOGLE_CLOUD_PROJECT:-oss-vdb-test}" \
OSV_VULNERABILITIES_BUCKET="${OSV_VULNERABILITIES_BUCKET:-osv-test-vulnerabilities}" \
./api-devserver >/dev/null 2>&1 &
SERVER_PID=$!

cleanup() {
  echo "Stopping API test server..."
  kill "$SERVER_PID" 2>/dev/null || true
  docker stop osv-esp >/dev/null 2>&1 || true
  rm -f "$ROOT_DIR/go/api-devserver"
}
trap cleanup EXIT INT TERM

# Wait for the API endpoint to be responsive (timeout after 30s)
echo "Waiting for API server to become ready..."
READY=0
for _ in $(seq 1 30); do
  if curl -s "http://localhost:8080/v1/vulns/GHSA-1" >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 1
done

if [ "$READY" -ne 1 ]; then
  echo "Error: API server failed to start within 30 seconds."
  exit 1
fi

echo "API server is ready. Running tests..."
cd "$SCRIPT_DIR"
go test ./...

#!/bin/bash
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

# Unit tests for docker/goose/entrypoint.bash using stubbed binaries on PATH.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENTRYPOINT="${SCRIPT_DIR}/entrypoint.bash"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

STUB_BIN="${TMPDIR}/bin"
mkdir -p "${STUB_BIN}"

cat > "${STUB_BIN}/curl" <<'EOF'
#!/bin/bash
for arg in "$@"; do
  if [[ "${arg}" == *"metadata.google.internal"* ]]; then
    if [[ -n "${STUB_METADATA_EMAIL:-}" ]]; then
      printf '%s' "${STUB_METADATA_EMAIL}"
      exit 0
    fi
    exit 22
  fi
  if [[ "${arg}" == *"/readiness"* ]]; then
    exit 0
  fi
done
exit 1
EOF

cat > "${STUB_BIN}/gcloud" <<'EOF'
#!/bin/bash
if [[ -n "${STUB_GCLOUD_ACCOUNT:-}" ]]; then
  printf '%s\n' "${STUB_GCLOUD_ACCOUNT}"
  exit 0
fi
exit 1
EOF

cat > "${STUB_BIN}/cloud-sql-proxy" <<'EOF'
#!/bin/bash
printf '%s\n' "$*" > "${STUB_LOG_DIR}/proxy_args"
sleep 30
EOF

cat > "${STUB_BIN}/goose" <<'EOF'
#!/bin/bash
printf '%s\n' "$*" > "${STUB_LOG_DIR}/goose_args"
printf '%s\n' "${GOOSE_DRIVER:-}" > "${STUB_LOG_DIR}/goose_driver"
printf '%s\n' "${GOOSE_DBSTRING:-}" > "${STUB_LOG_DIR}/goose_dbstring"
EOF

chmod +x "${STUB_BIN}/curl" "${STUB_BIN}/gcloud" "${STUB_BIN}/cloud-sql-proxy" "${STUB_BIN}/goose"

assert_eq() {
  local label="$1" got="$2" want="$3"
  if [[ "${got}" != "${want}" ]]; then
    echo "FAIL [${label}]: got '${got}', want '${want}'" >&2
    exit 1
  fi
}

# Case 1: Cloud Run Job mode (metadata server identity + CLOUDSQL_PRIVATE_IP=true + default PGROLE)
LOG1="${TMPDIR}/case1"
mkdir -p "${LOG1}"
PATH="${STUB_BIN}:${PATH}" \
  STUB_LOG_DIR="${LOG1}" \
  STUB_METADATA_EMAIL="db-migrator@oss-vdb.iam.gserviceaccount.com" \
  CLOUDSQL_INSTANCE="oss-vdb:us-central1:osv-db" \
  CLOUDSQL_PRIVATE_IP="true" \
  bash "${ENTRYPOINT}" up

assert_eq "case1 proxy args" "$(cat "${LOG1}/proxy_args")" \
  "oss-vdb:us-central1:osv-db --port=5432 --auto-iam-authn --health-check --http-port=9090 --private-ip"
assert_eq "case1 goose args" "$(cat "${LOG1}/goose_args")" "up"
assert_eq "case1 goose driver" "$(cat "${LOG1}/goose_driver")" "postgres"
assert_eq "case1 goose dbstring" "$(cat "${LOG1}/goose_dbstring")" \
  "host=127.0.0.1 port=5432 user=db-migrator@oss-vdb.iam dbname=osv sslmode=disable default_query_exec_mode=cache_describe role=cloudsqlsuperuser"

# Case 2: Fallback to gcloud auth + public IP default + explicit empty PGROLE disables startup role
LOG2="${TMPDIR}/case2"
mkdir -p "${LOG2}"
PATH="${STUB_BIN}:${PATH}" \
  STUB_LOG_DIR="${LOG2}" \
  STUB_GCLOUD_ACCOUNT="deployment@oss-vdb.iam.gserviceaccount.com" \
  CLOUDSQL_INSTANCE="private-osv:us-west2:osv-db" \
  PGROLE="" \
  bash "${ENTRYPOINT}" status

assert_eq "case2 proxy args" "$(cat "${LOG2}/proxy_args")" \
  "private-osv:us-west2:osv-db --port=5432 --auto-iam-authn --health-check --http-port=9090"
assert_eq "case2 goose args" "$(cat "${LOG2}/goose_args")" "status"
assert_eq "case2 goose dbstring" "$(cat "${LOG2}/goose_dbstring")" \
  "host=127.0.0.1 port=5432 user=deployment@oss-vdb.iam dbname=osv sslmode=disable default_query_exec_mode=cache_describe"

echo "PASS: docker/goose/entrypoint_test.bash"

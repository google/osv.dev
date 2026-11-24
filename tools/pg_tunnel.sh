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
#
# Port-forwards a local TCP port to a private-IP Cloud SQL PostgreSQL instance
# via the `pg-tunnel` / `pg-tunnel-read-pool` Deployment in the project's GKE
# `workers` cluster (using an isolated temporary KUBECONFIG).
#
# Usage:
#   tools/pg_tunnel.sh [project] [target] [local_port] [remote_port]
#
# Defaults to the read-only pool (`pg-tunnel-read-pool`) on oss-vdb / oss-vdb-test
# to avoid accidental writes or load on the primary instance (`pg-tunnel`).
# private-osv has no read pool, so it defaults to `pg-tunnel`.
#
# Examples:
#   tools/pg_tunnel.sh oss-vdb-test                       # staging read pool (:5432)
#   tools/pg_tunnel.sh oss-vdb '' 5433 6432               # prod read pool pooler (:6432)
#   tools/pg_tunnel.sh oss-vdb pg-tunnel                  # prod primary (writable, :5432)

set -euo pipefail

PROJECT="${1:-oss-vdb-test}"
LOCAL_PORT="${3:-5432}"
REMOTE_PORT="${4:-5432}"
CLUSTER_NAME="${CLUSTER_NAME:-workers}"

case "${PROJECT}" in
  oss-vdb)
    DEFAULT_ZONE="us-west2-c"
    DEFAULT_TARGET="pg-tunnel-read-pool"
    ;;
  oss-vdb-test)
    DEFAULT_ZONE="us-west2-b"
    DEFAULT_TARGET="pg-tunnel-read-pool"
    ;;
  private-osv)
    DEFAULT_ZONE="us-west2-c"
    DEFAULT_TARGET="pg-tunnel"
    ;;
  *)
    if [[ -z "${CLUSTER_ZONE:-}" ]]; then
      echo "Unknown project '${PROJECT}'. Set CLUSTER_ZONE=<zone> to override." >&2
      exit 1
    fi
    DEFAULT_ZONE="${CLUSTER_ZONE}"
    DEFAULT_TARGET="pg-tunnel-read-pool"
    ;;
esac

ZONE="${CLUSTER_ZONE:-${DEFAULT_ZONE}}"
TARGET="${2:-${DEFAULT_TARGET}}"

for cmd in gcloud kubectl; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "Missing required command: ${cmd}" >&2
    exit 1
  fi
done

KCFG=$(mktemp)
trap 'rm -f "${KCFG}"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "Fetching GKE credentials for ${PROJECT}/${ZONE}/${CLUSTER_NAME}..."
KUBECONFIG="${KCFG}" gcloud container clusters get-credentials \
  "${CLUSTER_NAME}" --zone="${ZONE}" --project="${PROJECT}" >/dev/null

ACCOUNT=$(gcloud config get-value account 2>/dev/null || true)
echo "Forwarding 127.0.0.1:${LOCAL_PORT} -> ${PROJECT} deploy/${TARGET}:${REMOTE_PORT}"
echo "Connect via IAM auth (token valid ~1h):"
echo "  PGSSLMODE=require PGPASSWORD=\$(gcloud sql generate-login-token) psql -h 127.0.0.1 -p ${LOCAL_PORT} -U ${ACCOUNT:-<you>@google.com} -d osv"
echo ""

KUBECONFIG="${KCFG}" kubectl port-forward -n default "deploy/${TARGET}" "${LOCAL_PORT}:${REMOTE_PORT}"

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
# Opens a temporary local TCP tunnel to a private-IP-only Cloud SQL PostgreSQL
# instance via an ephemeral socat Job/Pod in the project's GKE `workers` cluster.
#
# On Ctrl+C / exit, the Job (and its Pod) is deleted immediately. As a safeguard
# against crashes or abrupt disconnects, the Job also expires automatically after
# TTL_SECONDS (default: 28800 = 8h; set TTL_SECONDS=0 to disable) and Kubernetes
# garbage-collects it 60s later via ttlSecondsAfterFinished.
#
# Usage:
#   tools/pg_tunnel.sh [project] [instance] [local_port] [remote_port]
#
# Examples:
#   tools/pg_tunnel.sh oss-vdb-test                      # staging primary (:5432)
#   tools/pg_tunnel.sh oss-vdb osv-db-read-pool 5433 6432 # prod read pool PgBouncer
#   TTL_SECONDS=43200 tools/pg_tunnel.sh oss-vdb-test    # 12h tunnel deadline

set -euo pipefail

PROJECT="${1:-oss-vdb-test}"
INSTANCE="${2:-osv-db}"
LOCAL_PORT="${3:-5432}"
REMOTE_PORT="${4:-5432}"
CLUSTER_NAME="${CLUSTER_NAME:-workers}"
# Pinned multi-arch manifest list digest for alpine/socat:1.8.0.3.
SOCAT_IMAGE="${SOCAT_IMAGE:-alpine/socat:1.8.0.3@sha256:beb4a68d9e4fe6b0f21ea774a0fde6c31f580dde6368939ed70100c5385b015e}"
TTL_SECONDS="${TTL_SECONDS:-28800}"

if ! [[ "${LOCAL_PORT}" =~ ^[0-9]+$ ]] || (( LOCAL_PORT < 1 || LOCAL_PORT > 65535 )); then
  echo "LOCAL_PORT must be an integer between 1 and 65535 (got '${LOCAL_PORT}')." >&2
  exit 1
fi
if ! [[ "${REMOTE_PORT}" =~ ^[0-9]+$ ]] || (( REMOTE_PORT < 1024 || REMOTE_PORT > 65535 )); then
  echo "REMOTE_PORT must be an unprivileged port between 1024 and 65535 (got '${REMOTE_PORT}')." >&2
  exit 1
fi
if ! [[ "${TTL_SECONDS}" =~ ^[0-9]+$ ]]; then
  echo "TTL_SECONDS must be a non-negative integer (got '${TTL_SECONDS}')." >&2
  exit 1
fi

if [[ -n "${CLUSTER_ZONE:-}" ]]; then
  ZONE="${CLUSTER_ZONE}"
else
  case "${PROJECT}" in
    oss-vdb)      ZONE="us-west2-c" ;;
    oss-vdb-test) ZONE="us-west2-b" ;;
    private-osv)  ZONE="us-west2-c" ;;
    *)
      echo "Unknown project '${PROJECT}'. Set CLUSTER_ZONE=<zone> to override." >&2
      exit 1
      ;;
  esac
fi

for cmd in gcloud kubectl python3; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "Missing required command: ${cmd}" >&2
    exit 1
  fi
done

echo "Resolving private IP for ${PROJECT}/${INSTANCE}..."
INSTANCE_JSON=$(gcloud sql instances describe "${INSTANCE}" \
  --project="${PROJECT}" \
  --format=json)
PRIVATE_IP=$(
  python3 -c '
import json, sys
data = json.load(sys.stdin)
for entry in data.get("ipAddresses", []):
    if entry.get("type") == "PRIVATE":
        print(entry["ipAddress"])
        sys.exit(0)
' <<< "${INSTANCE_JSON}"
)
if [[ -z "${PRIVATE_IP}" ]]; then
  echo "Failed to resolve private IP for ${PROJECT}/${INSTANCE}." >&2
  exit 1
fi

TMP_KUBECONFIG=$(mktemp)
JOB_NAME=""
CLEANED_UP=false
cleanup() {
  if [[ "${CLEANED_UP}" == "true" ]]; then
    return
  fi
  CLEANED_UP=true
  # Ignore further interrupts so `kubectl delete` finishes cleanly on Ctrl+C.
  trap '' INT TERM HUP
  if [[ -n "${JOB_NAME}" ]]; then
    echo ""
    echo "Cleaning up tunnel job ${JOB_NAME}..."
    if ! KUBECONFIG="${TMP_KUBECONFIG}" kubectl delete job -n default "${JOB_NAME}" \
      --ignore-not-found --wait=false >/dev/null 2>&1; then
      echo "Warning: failed to delete job '${JOB_NAME}'. Run manually once reconnected:" >&2
      echo "  gcloud container clusters get-credentials ${CLUSTER_NAME} --zone=${ZONE} --project=${PROJECT}" >&2
      echo "  kubectl delete job -n default ${JOB_NAME}" >&2
    fi
  fi
  rm -f "${TMP_KUBECONFIG}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

echo "Fetching GKE credentials for ${PROJECT}/${ZONE}/${CLUSTER_NAME}..."
KUBECONFIG="${TMP_KUBECONFIG}" gcloud container clusters get-credentials \
  "${CLUSTER_NAME}" \
  --zone="${ZONE}" \
  --project="${PROJECT}" \
  >/dev/null

SAFE_USER=$(printf '%s' "${USER:-dev}" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9-')
SAFE_USER="${SAFE_USER:0:20}"
JOB_NAME="pg-tunnel-${SAFE_USER:-dev}-$$"

DEADLINE_LINE=""
if (( TTL_SECONDS > 0 )); then
  DEADLINE_LINE="  activeDeadlineSeconds: ${TTL_SECONDS}"
fi

echo "Starting ephemeral tunnel job ${JOB_NAME} -> ${PRIVATE_IP}:${REMOTE_PORT}..."
cat <<EOF | KUBECONFIG="${TMP_KUBECONFIG}" kubectl apply -n default -f - >/dev/null
apiVersion: batch/v1
kind: Job
metadata:
  name: ${JOB_NAME}
  namespace: default
  labels:
    app: pg-tunnel
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 60
${DEADLINE_LINE}
  template:
    metadata:
      labels:
        app: pg-tunnel
    spec:
      restartPolicy: Never
      automountServiceAccountToken: false
      containers:
        - name: socat
          image: ${SOCAT_IMAGE}
          args:
            - "TCP-LISTEN:${REMOTE_PORT},bind=127.0.0.1,fork,reuseaddr"
            - "TCP:${PRIVATE_IP}:${REMOTE_PORT}"
          ports:
            - containerPort: ${REMOTE_PORT}
          resources:
            requests:
              cpu: 10m
              memory: 16Mi
            limits:
              cpu: 100m
              memory: 64Mi
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 65534
            seccompProfile:
              type: RuntimeDefault
            capabilities:
              drop: ["ALL"]
EOF

POD_NAME=""
for _ in {1..30}; do
  POD_NAME=$(KUBECONFIG="${TMP_KUBECONFIG}" kubectl get pods -n default \
    -l "job-name=${JOB_NAME}" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
  if [[ -n "${POD_NAME}" ]]; then
    break
  fi
  sleep 1
done
if [[ -z "${POD_NAME}" ]]; then
  echo "Timed out waiting for pod created by job ${JOB_NAME}." >&2
  exit 1
fi

KUBECONFIG="${TMP_KUBECONFIG}" kubectl wait -n default \
  --for=condition=Ready "pod/${POD_NAME}" --timeout=120s >/dev/null

ACCOUNT=$(gcloud config get-value account 2>/dev/null || true)
ACCOUNT="${ACCOUNT:-<you>@google.com}"
echo ""
echo "Tunnel ready: 127.0.0.1:${LOCAL_PORT} -> ${PROJECT}/${INSTANCE} (${PRIVATE_IP}:${REMOTE_PORT})"
if (( TTL_SECONDS > 0 )); then
  echo "Auto-expiry: ${TTL_SECONDS}s (override with TTL_SECONDS=<secs>, 0 to disable)"
fi
echo "Connect in another terminal via personal IAM auth (token valid ~1h):"
echo "  PGSSLMODE=require PGPASSWORD=\$(gcloud sql generate-login-token) psql -h 127.0.0.1 -p ${LOCAL_PORT} -U ${ACCOUNT} -d osv"
echo ""
echo "Press Ctrl+C to close the tunnel and delete job ${JOB_NAME}."
KUBECONFIG="${TMP_KUBECONFIG}" kubectl port-forward -n default "pod/${POD_NAME}" "${LOCAL_PORT}:${REMOTE_PORT}"

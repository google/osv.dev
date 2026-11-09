#!/bin/bash
#
# Goose + Cloud SQL Auth Proxy cloud builder entry point.
set -euo pipefail

if [[ "${1:-}" == "version" || "${1:-}" == "-version" || "${1:-}" == "--version" ]]; then
  goose -version
  cloud-sql-proxy --version
  exit 0
fi

if [[ -n "${CLOUDSQL_INSTANCE:-}" ]]; then
  active_account=$(gcloud auth list --filter=status:ACTIVE --format="value(account)" 2> /dev/null)
  if [[ -z "${active_account}" ]]; then
    echo "No active gcloud account found for Cloud SQL IAM authentication."
    exit 1
  fi

  echo "Starting cloud-sql-proxy for ${CLOUDSQL_INSTANCE}..."
  cloud-sql-proxy "${CLOUDSQL_INSTANCE}" \
    --port=5432 \
    --auto-iam-authn \
    --health-check \
    --http-port=9090 &
  PROXY_PID=$!
  trap 'kill "${PROXY_PID}" 2>/dev/null || true' EXIT

  ready=false
  for _ in {1..30}; do
    if ! kill -0 "${PROXY_PID}" 2>/dev/null; then
      echo "cloud-sql-proxy exited unexpectedly."
      wait "${PROXY_PID}" || true
      exit 1
    fi
    if curl -sf http://127.0.0.1:9090/readiness >/dev/null 2>&1; then
      ready=true
      break
    fi
    sleep 1
  done

  if [[ "${ready}" != "true" ]]; then
    echo "Timed out waiting for cloud-sql-proxy readiness."
    exit 1
  fi

  # Cloud SQL IAM service account usernames omit the .gserviceaccount.com suffix.
  db_user="${PGUSER:-${active_account%.gserviceaccount.com}}"
  db_name="${PGDATABASE:-osv}"
  export GOOSE_DRIVER="${GOOSE_DRIVER:-postgres}"
  export GOOSE_DBSTRING="${GOOSE_DBSTRING:-host=127.0.0.1 port=5432 user=${db_user} dbname=${db_name} sslmode=disable options=-crole=cloudsqlsuperuser}"
fi

echo "Running: goose $*"
goose "$@"

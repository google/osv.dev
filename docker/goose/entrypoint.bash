#!/bin/bash
#
# Goose + Cloud SQL Auth Proxy cloud builder entry point.
set -euo pipefail

if [[ "${1:-}" == "version" || "${1:-}" == "-version" || "${1:-}" == "--version" ]]; then
  goose -version
  cloud-sql-proxy --version
  exit 0
fi

active_account=""
function get-active-account() {
  active_account=$(gcloud auth list --filter=status:ACTIVE --format="value(account)" 2> /dev/null)
}

function activate-service-key() {
  rootdir=/root/.config/gcloud-config
  mkdir -p "$rootdir"
  tmpdir=$(mktemp -d "$rootdir/servicekey.XXXXXXXX")
  trap 'rm -rf "$tmpdir"' EXIT
  echo "${GCLOUD_SERVICE_KEY}" | base64 --decode -i > "${tmpdir}/gcloud-service-key.json"
  gcloud auth activate-service-account --key-file "${tmpdir}/gcloud-service-key.json" --quiet
  get-active-account
}

function service-account-usage() {
  cat <<EOF
No account is set. This is either provided by the Google cloud builder environment, or by providing a
key file through environment variables, e.g. set
  GCLOUD_SERVICE_KEY=<base64 encoded service account key file>
EOF
  exit 1
}

function account-active-warning() {
  cat <<EOF
A service account key file has been provided in the environment variable GCLOUD_SERVICE_KEY. This account will
be activated, which will override the account already activated in this container.
EOF
}

get-active-account
if [[ -n "$active_account" && -n "${GCLOUD_SERVICE_KEY:-}" ]]; then
  account-active-warning
  activate-service-key
elif [[ -z "$active_account" && -n "${GCLOUD_SERVICE_KEY:-}" ]]; then
  activate-service-key
elif [[ -z "$active_account" && -z "${GCLOUD_SERVICE_KEY:-}" ]]; then
  echo "no active account and no key"
  service-account-usage
fi

if [[ -n "${CLOUDSQL_INSTANCE:-}" ]]; then
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

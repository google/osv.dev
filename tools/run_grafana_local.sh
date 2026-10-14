#!/bin/bash

# tools/run_grafana_local.sh

set -e

# Ensure we are in the root of the repo
if [ ! -f "Makefile" ]; then
    echo "This script must be run from the root of the repository."
    exit 1
fi

# Check for ADC
if [ ! -f "$HOME/.config/gcloud/application_default_credentials.json" ]; then
    echo "GCP Application Default Credentials not set."
    echo "Please run: gcloud auth application-default login"
    exit 1
fi

GCP_PROJECT=${1:-oss-vdb-test}
MONITORING_DIR="deployment/clouddeploy/gke-workers/environments/oss-vdb-test/monitoring"

# Create a temporary directory for local configuration
TMP_DIR=$(mktemp -d)
# Trap to cleanup on exit
trap "rm -rf $TMP_DIR; docker stop grafana-local gmp-frontend-local 2>/dev/null || true; docker network rm grafana-local-net 2>/dev/null || true" EXIT

# Create a private Docker network
docker network create grafana-local-net 2>/dev/null || true

# Extract datasources.yaml from configmap
# We use the container name as the hostname
cat <<EOF > "$TMP_DIR/datasources.yaml"
apiVersion: 1
datasources:
  - name: GMP (Prometheus)
    uid: gmp
    type: prometheus
    access: proxy
    url: http://gmp-frontend-local:9090
    isDefault: true
    editable: true
    jsonData:
      httpMethod: POST
      timeInterval: 15s
  - name: Cloud Monitoring
    uid: cloud-monitoring
    type: googlecloud-monitoring-datasource
    access: proxy
    editable: true
    jsonData:
      authenticationType: gce
      defaultProject: $GCP_PROJECT
EOF

# Extract dashboards.yaml provider
cat <<EOF > "$TMP_DIR/dashboards.yaml"
apiVersion: 1
providers:
  - name: 'default'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    editable: true # Allow editing locally
    options:
      path: /etc/grafana/dashboards
EOF

echo "Starting GMP Frontend..."
docker run -d --rm \
  --name gmp-frontend-local \
  --network grafana-local-net \
  -v "$HOME/.config/gcloud/application_default_credentials.json:/tmp/keys/adc.json:ro" \
  -e GOOGLE_APPLICATION_CREDENTIALS=/tmp/keys/adc.json \
  gke.gcr.io/prometheus-engine/frontend:v0.18.2-gke.1@sha256:35ab356d969255dd7694ae371bf0991b97907451b4c7e1574b58a096d3be5977 \
  --web.listen-address=0.0.0.0:9090 \
  --query.project-id=$GCP_PROJECT

echo "Starting Grafana on http://localhost:3000"
echo "Login skipped (Anonymous access enabled as Admin)"
echo "To save changes: Edit dashboard in UI -> Settings -> JSON Model -> Copy -> Save to file"

# Open browser automatically in background
(
  # Wait for Grafana to be ready
  for i in {1..30}; do
    if curl -s -o /dev/null http://localhost:3000/api/health; then
      echo "Grafana is ready! Opening browser..."
      if command -v xdg-open > /dev/null; then
        xdg-open http://localhost:3000 > /dev/null 2>&1
      elif command -v open > /dev/null; then
        open http://localhost:3000 > /dev/null 2>&1
      else
        echo "Could not find a command to open browser. Please open http://localhost:3000 manually."
      fi
      break
    fi
    sleep 1
  done
) &

# Run Grafana
# Anonymous access is enabled as Admin for local development convenience ONLY.
# Do NOT use these settings in production!
docker run --rm \
  --name grafana-local \
  --network grafana-local-net \
  -p 127.0.0.1:3000:3000 \
  -e GF_AUTH_ANONYMOUS_ENABLED="true" \
  -e GF_AUTH_ANONYMOUS_ORG_ROLE="Admin" \
  -v "$TMP_DIR/datasources.yaml:/etc/grafana/provisioning/datasources/datasources.yaml:ro" \
  -v "$TMP_DIR/dashboards.yaml:/etc/grafana/provisioning/dashboards/dashboards.yaml:ro" \
  -v "$(pwd)/$MONITORING_DIR/dashboards:/etc/grafana/dashboards:ro" \
  grafana/grafana:11.5.10@sha256:4d1b2146de6488324c4e880be2028620259c414406e36a9ac2160485f8fd3259

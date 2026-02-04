#!/bin/bash
# High-level CI Test Orchestration Script
set -euo pipefail

# 1. Dependency Management
# Optimized for Cloud Build environments to reduce container overhead
if [[ -z "${CLOUDBUILD:-}" ]]; then
  echo "--- Environment: Local. Synchronizing dependencies... ---"
  poetry sync
else
  echo "--- Environment: Cloud Build. Skipping dependency sync... ---"
fi

# 2. Core Library Unit Tests
# Explicitly testing critical OSV modules
echo "--- Running Core Module Tests ---"
CORE_MODULES=(
  osv.bug_test
  osv.purl_helpers_test
  osv.request_helper_test
  osv.semver_index_test
  osv.pubsub_test
  osv.impact_test
  osv.models_test
)

for module in "${CORE_MODULES[@]}"; do
  poetry run python -m unittest "$module"
done

# 3. Ecosystem Discovery Tests
# Replaces individual file calls with automated discovery
echo "--- Running Ecosystem Discovery Tests ---"
poetry run python -m unittest discover -p "*_test.py" -s osv/ecosystems/ -t .

# 4. Cross-Language Model Validation
# Ensures Go/Python datastore consistency
echo "--- Running Go/Python Model Validation ---"
(
  cd ./go/osv/models/internal/validate/ || exit 1
  chmod +x run_validate.sh
  ./run_validate.sh
)

echo "--- All checks completed successfully ---"

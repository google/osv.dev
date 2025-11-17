#!/bin/bash -ex

poetry install
poetry run python -m unittest osv.bug_test
poetry run python -m unittest osv.purl_helpers_test
poetry run python -m unittest osv.request_helper_test
poetry run python -m unittest osv.semver_index_test
poetry run python -m unittest osv.pubsub_test
poetry run python -m unittest osv.impact_test
poetry run python -m unittest osv.models_test

# Run all osv.ecosystems tests
poetry run python -m unittest discover osv/ecosystems/ "*_test.py" .

# Run the validation for the go/python datastore models
cd ./go/models/internal/validate/ && ./run_validate.sh

# Run the API tester
url="localhost:${DATASTORE_EMULATOR_PORT}"

cd ./tools/apitester/ && OSV_API_BASE_URL="$url" go test ./...

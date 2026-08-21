# Copyright 2022 Google LLC
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

install-cmd := poetry install
run-cmd := poetry run

lib-tests: ## Run core Python library tests
	./run_tests.sh

vanir-signatures-tests: ## Run Vanir signatures tests
	cd gcp/workers/vanir_signatures && ./run_tests.sh

website-tests: ## Run legacy Python website tests
	cd gcp/website && ./run_tests.sh

vulnfeed-tests: ## Run Go vulnfeeds tests
	cd vulnfeeds && ./run_tests.sh

bindings-tests: ## Run API bindings tests
	cd bindings && ./run_tests.sh

go-tests: ## Run Go services tests
	cd go && ./run_tests.sh

api-server-tests: ## Run Go API server integration tests
	./tools/apitester/run_tests.sh

update-api-snapshots: ## Update API query snapshots
	UPDATE_SNAPS=true ./tools/apitester/run_tests.sh

lint: ## Run linters and format checks
	GOTOOLCHAIN=auto $(run-cmd) tools/lint_and_format.sh

build-osv-protos:
	cd osv && $(run-cmd) python -m grpc_tools.protoc --python_out=. --mypy_out=. --proto_path=. --proto_path=osv-schema/proto vulnerability.proto importfinding.proto

build-api-protos:
	cd proto/v1 && protoc \
      --include_imports \
      --include_source_info \
      --proto_path=.. \
      --proto_path=. \
      --proto_path=../../osv \
      --proto_path=../../osv/osv-schema/proto \
      --descriptor_set_out=api_descriptor.pb \
      vulnerability.proto importfinding.proto osv_service_v1.proto
	cd osv && protoc \
      --proto_path=. \
      --go_out=paths=source_relative:../bindings/go/api \
      importfinding.proto
	cd proto/v1 && protoc \
      --proto_path=.. \
      --proto_path=. \
      --proto_path=../../osv \
      --proto_path=../../osv/osv-schema/proto \
      --go_out=paths=source_relative:../../bindings/go/api \
      --go-grpc_out=paths=source_relative:../../bindings/go/api \
      osv_service_v1.proto

build-protos: build-osv-protos build-api-protos ## Build all protocol buffers

build-swagger: ## Build Swagger/OpenAPI documentation
	./docs/build_swagger.sh

build-website-frontend:
	cd website/frontend3 && pnpm install && pnpm run build
	cd website/blog && hugo --buildFuture -d ../dist/static/blog

run-website: build-website-frontend ## Run local Python website against prod Datastore
	cd gcp/website && $(install-cmd) && GOOGLE_CLOUD_PROJECT=oss-vdb OSV_VULNERABILITIES_BUCKET=osv-vulnerabilities $(run-cmd) python main.py

run-website-staging: build-website-frontend
	cd gcp/website && $(install-cmd) && GOOGLE_CLOUD_PROJECT=oss-vdb-test OSV_VULNERABILITIES_BUCKET=osv-test-vulnerabilities $(run-cmd) python main.py

run-website-emulator: build-website-frontend ## Run local Python website against emulator
	cd gcp/website && $(install-cmd) && DATASTORE_EMULATOR_PORT=5002 $(run-cmd) python frontend_emulator.py

run-go-website: build-website-frontend ## Run local Go website against prod Datastore
	cd go && GOOGLE_CLOUD_PROJECT=oss-vdb OSV_VULNERABILITIES_BUCKET=osv-vulnerabilities go run ./cmd/website -static-dir ../website/dist -docs-dir ../docs

run-go-website-staging: build-website-frontend
	cd go && GOOGLE_CLOUD_PROJECT=oss-vdb-test OSV_VULNERABILITIES_BUCKET=osv-test-vulnerabilities go run ./cmd/website -static-dir ../website/dist -docs-dir ../docs

run-go-website-emulator: build-website-frontend ## Run local Go website against emulator
	cd go && DATASTORE_EMULATOR_HOST=localhost:5002 go run ./cmd/website -static-dir ../website/dist -docs-dir ../docs

stage-website-assets: build-website-frontend
	mkdir -p go/cmd/website/dist go/cmd/website/docs
	cp -r website/dist/* go/cmd/website/dist/
	cp docs/osv_service_v1.swagger.json go/cmd/website/docs/

run-go-website-prod: stage-website-assets
	cd go && GOOGLE_CLOUD_PROJECT=oss-vdb OSV_VULNERABILITIES_BUCKET=osv-vulnerabilities go run -tags embedstatic ./cmd/website



# Run with `make run-api-server ARGS=--no-backend` to launch esp without backend.
# Run the Go developer server orchestrator (launches both ESPv2 and the Go API server).
# Run with `make run-api-server ARGS=--no-backend` to launch esp without backend.
run-api-server: ## Run local Go API server with ESPv2 proxy
	test -f $(HOME)/.config/gcloud/application_default_credentials.json || (echo "GCP Application Default Credentials not set, try 'gcloud auth application-default login'"; exit 1)
	docker inspect osv/esp:latest >/dev/null 2>&1 || docker build -f docker/esp/Dockerfile -t osv/esp:latest docker/esp
	@cd go && go build -o ./api-devserver ./cmd/api-devserver && (GOOGLE_CLOUD_PROJECT=oss-vdb OSV_VULNERABILITIES_BUCKET=osv-vulnerabilities ./api-devserver $(ARGS); EXIT_CODE=$$?; rm -f ./api-devserver; exit $$EXIT_CODE)

# Run the Go developer server orchestrator against the staging/test environment.
run-api-server-test:
	test -f $(HOME)/.config/gcloud/application_default_credentials.json || (echo "GCP Application Default Credentials not set, try 'gcloud auth application-default login'"; exit 1)
	docker inspect osv/esp:latest >/dev/null 2>&1 || docker build -f docker/esp/Dockerfile -t osv/esp:latest docker/esp
	@cd go && go build -o ./api-devserver ./cmd/api-devserver && (GOOGLE_CLOUD_PROJECT=oss-vdb-test OSV_VULNERABILITIES_BUCKET=osv-test-vulnerabilities ./api-devserver $(ARGS); EXIT_CODE=$$?; rm -f ./api-devserver; exit $$EXIT_CODE)

# TODO: API integration tests.
all-tests: lib-tests website-tests vulnfeed-tests bindings-tests go-tests ## Run all tests

reimport-tui: ## Run the reimport TUI tool
	test -f $(HOME)/.config/gcloud/application_default_credentials.json || (echo "GCP Application Default Credentials not set, try 'gcloud auth application-default login'"; exit 1)
	cd go/cmd/tools/reimport-tui && go run .

.PHONY: help
help: ## Show this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-30s\033[0m %s\n", $$1, $$2}'

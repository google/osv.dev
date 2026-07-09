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

lib-tests:
	./run_tests.sh

worker-tests:
	git submodule update --init --recursive
	cd gcp/workers/worker && ./run_tests.sh

importer-tests:
	cd gcp/workers/importer && ./run_tests.sh

recoverer-tests:
	cd gcp/workers/recoverer && ./run_tests.sh

vanir-signatures-tests:
	cd gcp/workers/vanir_signatures && ./run_tests.sh

website-tests:
	cd gcp/website && ./run_tests.sh

vulnfeed-tests:
	cd vulnfeeds && ./run_tests.sh

bindings-tests:
	cd bindings && ./run_tests.sh

go-tests:
	cd go && ./run_tests.sh

api-server-tests:
	test -f $(HOME)/.config/gcloud/application_default_credentials.json || (echo "GCP Application Default Credentials not set, try 'gcloud auth application-default login'"; exit 1)
	cd go && go build -o ./api ./cmd/api
	cd gcp/api && docker build -f Dockerfile.esp -t osv/esp:latest .
	cd gcp/api && OSV_USE_GO_BACKEND=1 ./run_tests.sh $(HOME)/.config/gcloud/application_default_credentials.json
	cd gcp/api && OSV_USE_GO_BACKEND=1 ./run_tests_e2e.sh $(HOME)/.config/gcloud/application_default_credentials.json

update-api-snapshots:
	test -f $(HOME)/.config/gcloud/application_default_credentials.json || (echo "GCP Application Default Credentials not set, try 'gcloud auth application-default login'"; exit 1)
	cd go && go build -o ./api ./cmd/api
	cd gcp/api && docker build -f Dockerfile.esp -t osv/esp:latest .
	cd gcp/api && UPDATE_SNAPS=true OSV_USE_GO_BACKEND=1 ./run_tests_e2e.sh $(HOME)/.config/gcloud/application_default_credentials.json

lint:
	GOTOOLCHAIN=auto $(run-cmd) tools/lint_and_format.sh

build-osv-protos:
	cd osv && $(run-cmd) python -m grpc_tools.protoc --python_out=. --mypy_out=. --proto_path=. --proto_path=osv-schema/proto vulnerability.proto importfinding.proto

build-api-protos:
	cd gcp/api/v1 && $(run-cmd) python -m grpc_tools.protoc \
      --include_imports \
      --include_source_info \
      --proto_path=googleapis \
      --proto_path=. \
      --proto_path=osv \
      --proto_path=osv/osv-schema/proto \
      --descriptor_set_out=api_descriptor.pb \
      --python_out=.. \
      --grpc_python_out=.. \
      --mypy_out=.. \
      vulnerability.proto importfinding.proto osv_service_v1.proto
	cd osv && protoc \
      --proto_path=. \
      --go_out=paths=source_relative:../bindings/go/api \
      importfinding.proto
	cd gcp/api/v1 && protoc \
      --proto_path=googleapis \
      --proto_path=. \
      --proto_path=osv \
      --proto_path=osv/osv-schema/proto \
      --go_out=paths=source_relative:../../../bindings/go/api \
      --go-grpc_out=paths=source_relative:../../../bindings/go/api \
      osv_service_v1.proto

build-protos: build-osv-protos build-api-protos

run-website:
	cd gcp/website/frontend3 && pnpm install && pnpm run build
	cd gcp/website/blog && hugo --buildFuture -d ../dist/static/blog
	cd gcp/website && $(install-cmd) && GOOGLE_CLOUD_PROJECT=oss-vdb OSV_VULNERABILITIES_BUCKET=osv-vulnerabilities $(run-cmd) python main.py

run-website-staging:
	cd gcp/website/frontend3 && pnpm install && pnpm run build
	cd gcp/website/blog && hugo --buildFuture -d ../dist/static/blog
	cd gcp/website && $(install-cmd) && GOOGLE_CLOUD_PROJECT=oss-vdb-test OSV_VULNERABILITIES_BUCKET=osv-test-vulnerabilities $(run-cmd) python main.py

run-website-emulator:
	cd gcp/website/frontend3 && pnpm install && pnpm run build
	cd gcp/website/blog && hugo --buildFuture -d ../dist/static/blog
	cd gcp/website && $(install-cmd) && DATASTORE_EMULATOR_PORT=5002 $(run-cmd) python frontend_emulator.py

# Run with `make run-api-server ARGS=--no-backend` to launch esp without backend.
# Run the Go developer server orchestrator (launches both ESPv2 and the Go API server).
# Run with `make run-api-server ARGS=--no-backend` to launch esp without backend.
run-api-server:
	test -f $(HOME)/.config/gcloud/application_default_credentials.json || (echo "GCP Application Default Credentials not set, try 'gcloud auth application-default login'"; exit 1)
	docker inspect osv/esp:latest >/dev/null 2>&1 || (cd gcp/api && docker build -f Dockerfile.esp -t osv/esp:latest .)
	@cd go && go build -o ./api-devserver ./cmd/api-devserver && (GOOGLE_CLOUD_PROJECT=oss-vdb OSV_VULNERABILITIES_BUCKET=osv-vulnerabilities ./api-devserver $(ARGS); EXIT_CODE=$$?; rm -f ./api-devserver; exit $$EXIT_CODE)

# Run the Go developer server orchestrator against the staging/test environment.
run-api-server-test:
	test -f $(HOME)/.config/gcloud/application_default_credentials.json || (echo "GCP Application Default Credentials not set, try 'gcloud auth application-default login'"; exit 1)
	docker inspect osv/esp:latest >/dev/null 2>&1 || (cd gcp/api && docker build -f Dockerfile.esp -t osv/esp:latest .)
	@cd go && go build -o ./api-devserver ./cmd/api-devserver && (GOOGLE_CLOUD_PROJECT=oss-vdb-test OSV_VULNERABILITIES_BUCKET=osv-test-vulnerabilities ./api-devserver $(ARGS); EXIT_CODE=$$?; rm -f ./api-devserver; exit $$EXIT_CODE)

# Legacy Python API server targets
run-python-api-server:
	test -f $(HOME)/.config/gcloud/application_default_credentials.json || (echo "GCP Application Default Credentials not set, try 'gcloud auth application-default login'"; exit 1)
	cd gcp/api && docker build -f Dockerfile.esp -t osv/esp:latest .
	cd gcp/api && $(install-cmd) && GOOGLE_CLOUD_PROJECT=oss-vdb OSV_VULNERABILITIES_BUCKET=osv-vulnerabilities $(run-cmd) python test_server.py $(HOME)/.config/gcloud/application_default_credentials.json $(ARGS)

run-python-api-server-test:
	test -f $(HOME)/.config/gcloud/application_default_credentials.json || (echo "GCP Application Default Credentials not set, try 'gcloud auth application-default login'"; exit 1)
	cd gcp/api && docker build -f Dockerfile.esp -t osv/esp:latest .
	cd gcp/api && $(install-cmd) && GOOGLE_CLOUD_PROJECT=oss-vdb-test OSV_VULNERABILITIES_BUCKET=osv-test-vulnerabilities $(run-cmd) python test_server.py $(HOME)/.config/gcloud/application_default_credentials.json $(ARGS)

# TODO: API integration tests.
all-tests: lib-tests worker-tests importer-tests recoverer-tests website-tests vulnfeed-tests bindings-tests go-tests

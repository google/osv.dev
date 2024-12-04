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

alias-tests:
	cd gcp/workers/alias && ./run_tests.sh

website-tests:
	cd gcp/website && ./run_tests.sh

vulnfeed-tests:
	cd vulnfeeds && ./run_tests.sh

api-server-tests:
	test -f $(HOME)/.config/gcloud/application_default_credentials.json || (echo "GCP Application Default Credentials not set, try 'gcloud auth login --update-adc'"; exit 1)
	cd gcp/api && docker build -f Dockerfile.esp -t osv/esp:latest .
	cd gcp/api && ./run_tests.sh $(HOME)/.config/gcloud/application_default_credentials.json

lint:
	tools/lint_and_format.sh

run-website:
	cd gcp/website/frontend3 && npm install && npm run build
	cd gcp/website/blog && hugo --buildFuture -d ../dist/static/blog
	cd gcp/website && $(install-cmd) && GOOGLE_CLOUD_PROJECT=oss-vdb $(run-cmd) python main.py

run-website-staging:
	cd gcp/website/frontend3 && npm install && npm run build
	cd gcp/website/blog && hugo --buildFuture -d ../dist/static/blog
	cd gcp/website && $(install-cmd) && GOOGLE_CLOUD_PROJECT=oss-vdb-test $(run-cmd) python main.py

# Run with `make run-api-server ARGS=--no-backend` to launch esp without backend.
run-api-server:
	test -f $(HOME)/.config/gcloud/application_default_credentials.json || (echo "GCP Application Default Credentials not set, try 'gcloud auth login --update-adc'"; exit 1)
	cd gcp/api && docker build -f Dockerfile.esp -t osv/esp:latest .
	cd gcp/api && $(install-cmd) && GOOGLE_CLOUD_PROJECT=oss-vdb $(run-cmd) python test_server.py $(HOME)/.config/gcloud/application_default_credentials.json $(ARGS)

# TODO: API integration tests.
all-tests: lib-tests worker-tests importer-tests alias-tests website-tests vulnfeed-tests

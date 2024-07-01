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
lib-tests:
	./run_tests.sh

worker-tests:
	git submodule update --init --recursive
	cd docker/worker && ./run_tests.sh

importer-tests:
	cd docker/importer && ./run_tests.sh

alias-tests:
	cd docker/alias && ./run_tests.sh

appengine-tests:
	cd gcp/appengine && ./run_tests.sh

vulnfeed-tests:
	cd vulnfeeds && ./run_tests.sh

api-server-tests:
	test -f $(HOME)/.config/gcloud/application_default_credentials.json || (echo "GCP Application Default Credentials not set, try 'gcloud auth login --update-adc'"; exit 1)
	cd gcp/api && docker build -f Dockerfile.esp -t osv/esp:latest .
	cd gcp/api && ./run_tests.sh $(HOME)/.config/gcloud/application_default_credentials.json

lint:
	tools/lint_and_format.sh

run-appengine:
	cd gcp/appengine/frontend3 && npm install && npm run build
	cd gcp/appengine/blog && hugo -d ../dist/static/blog
	cd gcp/appengine && poetry install && GOOGLE_CLOUD_PROJECT=oss-vdb poetry run python main.py

run-appengine-staging:
	cd gcp/appengine/frontend3 && npm install && npm run build
	cd gcp/appengine/blog && hugo -d ../dist/static/blog
	cd gcp/appengine && poetry install && GOOGLE_CLOUD_PROJECT=oss-vdb-test poetry run python main.py

run-api-server:
	test -f $(HOME)/.config/gcloud/application_default_credentials.json || (echo "GCP Application Default Credentials not set, try 'gcloud auth login --update-adc'"; exit 1)
	cd gcp/api && docker build -f Dockerfile.esp -t osv/esp:latest .
	cd gcp/api && poetry install && GOOGLE_CLOUD_PROJECT=oss-vdb poetry run python test_server.py $(HOME)/.config/gcloud/application_default_credentials.json

# TODO: API integration tests.
all-tests: lib-tests worker-tests importer-tests alias-tests appengine-tests vulnfeed-tests

# Copyright 2024 Google LLC
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

FROM gcr.io/oss-vdb/worker

WORKDIR /staging_api_test

COPY retrieve_bugs_from_bucket.py perform_api_calls.py run.sh ./

# Add aiohttp lib
RUN cd /env/docker/worker && POETRY_VIRTUALENVS_CREATE=false poetry add aiohttp

RUN chmod 755 retrieve_bugs_from_bucket.py perform_api_calls.py run.sh

ENTRYPOINT ["./run.sh"]

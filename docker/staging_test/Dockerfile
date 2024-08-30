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

WORKDIR /staging_testing

COPY retrieve_bugs_from_db.py /staging_testing
COPY perform_api_calls.py /staging_testing
COPY run.sh /staging_testing

# Add aiohttp lib
RUN cd /env/docker/worker && POETRY_VIRTUALENVS_CREATE=false poetry add aiohttp

RUN chmod 755 /staging_testing/retrieve_bugs_from_db.py
RUN chmod 755 /staging_testing/perform_api_calls.py
RUN chmod 755 /staging_testing/run.sh

ENTRYPOINT ["/staging_testing/run.sh"]

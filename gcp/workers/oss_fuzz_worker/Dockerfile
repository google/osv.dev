# Copyright 2021 Google LLC
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

FROM gcr.io/oss-vdb/worker-base

RUN mkdir /work && mkdir -p /env/gcp/workers/worker
VOLUME /var/lib/docker

# Replicate project structure to make relative editable poetry dependency work.
# Install dependencies before copying osv/ so edits to osv/ don't bust the poetry layer.
COPY gcp/workers/oss_fuzz_worker/poetry.lock gcp/workers/oss_fuzz_worker/pyproject.toml /env/gcp/workers/worker/
COPY poetry.lock pyproject.toml README.md /env/

# Create a minimal osv package stub so Poetry installs all third-party deps and the
# editable osv link in a cacheable layer before copying the real osv/ source tree.
RUN mkdir -p /env/osv && touch /env/osv/__init__.py && \
    cd /env/gcp/workers/worker && POETRY_VIRTUALENVS_CREATE=false poetry install

COPY osv /env/osv

COPY gcp/workers/oss_fuzz_worker/oss_fuzz.py gcp/workers/oss_fuzz_worker/worker.py /usr/local/bin/
RUN chmod 755 /usr/local/bin/worker.py

ENTRYPOINT ["worker.py"]

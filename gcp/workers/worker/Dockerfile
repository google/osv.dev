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

RUN apt-get update && apt-get upgrade -y

RUN mkdir /work && mkdir -p /env/gcp/workers/worker
VOLUME /var/lib/docker

# Replicate project structure to make relative editable poetry dependency work.
# TODO(ochang): Just copy the entire project (needs a clean checkout).
COPY gcp/workers/worker/poetry.lock gcp/workers/worker/pyproject.toml /env/gcp/workers/worker/
COPY poetry.lock pyproject.toml README.md /env/
COPY osv /env/osv

# Set virtualenv creation to false to install globally
RUN cd /env/gcp/workers/worker && POETRY_VIRTUALENVS_CREATE=false poetry install

COPY gcp/workers/worker/oss_fuzz.py gcp/workers/worker/worker.py /usr/local/bin/
RUN chmod 755 /usr/local/bin/worker.py

ENTRYPOINT ["worker.py"]

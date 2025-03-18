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

FROM python:3.12.8-slim@sha256:143496c4e492ee45436fb1ac222714990b58a02f2eafe5eb2622b1427a8301c6

# Install build-essential which is required by Cloud Profiler
RUN apt-get update && apt-get install -y build-essential

# Generation 1 of cloud run overrides the HOME environment variable, causing
# poetry to run in the incorrect environment, as it defaults to using $HOME/.cache/virtualenvs/...
# 
# This forces it to create the virtualenv in the same directory as the project, avoiding this issue.
ENV POETRY_VIRTUALENVS_IN_PROJECT=true
ENV POETRY_HOME "/opt/poetry"
COPY docker/poetry/requirements.txt ./poetry-requirements.txt
RUN python3 -m venv $POETRY_HOME && \
    $POETRY_HOME/bin/pip install --require-hashes -r ./poetry-requirements.txt && \
    ln -s $POETRY_HOME/bin/poetry /usr/local/bin/poetry

# TODO(ochang): Just copy the entire project (needs a clean checkout).
COPY pyproject.toml poetry.lock README.md /osv/
COPY osv /osv/osv
COPY gcp/api /osv/gcp/api

WORKDIR /osv/gcp/api
RUN poetry install

ENTRYPOINT ["poetry", "run", "python", "/osv/gcp/api/server.py"]

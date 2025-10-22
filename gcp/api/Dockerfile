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

FROM python:3.13.3-slim@sha256:56a11364ffe0fee3bd60af6d6d5209eba8a99c2c16dc4c7c5861dc06261503cc

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

# Generate the Python Protobuf code
RUN chmod +x gen-proto.sh && ./gen-proto.sh

ENTRYPOINT ["poetry", "run", "python", "/osv/gcp/api/server.py"]

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

FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:485.0.0-alpine@sha256:d5da0344b23d03a6f2728657732c7a60300a91acaad9b8076c6fd30b1dfe1ff4

# Setup Poetry in its own virtual environment.
# So when poetry changes the system dependencies, it doesn't mess with its own dependencies
# when managing our dependencies.
# See: https://python-poetry.org/docs/#installation 
ENV POETRY_HOME "/opt/poetry"
COPY docker/poetry/requirements.txt ./poetry-requirements.txt
RUN python3 -m venv $POETRY_HOME && \
    $POETRY_HOME/bin/pip install --require-hashes -r ./poetry-requirements.txt && \
    ln -s $POETRY_HOME/bin/poetry /usr/local/bin/poetry

# Keep the virtualenv directly in the project directory. This isn't strictly neccesary for
# this project as it runs on kubernetes, but it keeps it consistent with other cloud run images
ENV POETRY_VIRTUALENVS_IN_PROJECT=true

RUN mkdir /src
WORKDIR /src

ENV PIP_NO_BINARY ""
COPY vulnfeeds/tools/debian /src

ENV LANG en_US.UTF-8
RUN cd debian_converter && poetry install

RUN chmod +x /src/run_*

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

FROM ubuntu:20.04

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y \
    apt-transport-https \
    build-essential \
    ca-certificates \
    curl \
    git \
    gnupg-agent \
    zlib1g-dev \
    libffi-dev \
    libssl-dev \
    software-properties-common

ARG PYTHON_VERSION=3.11.4
RUN curl -sS https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tgz | tar -C /tmp -xzv && \
    cd /tmp/Python-${PYTHON_VERSION} && \
    ./configure --enable-optimizations --with-lto --enable-loadable-sqlite-extensions && \
    make -j && \
    make install && \
    rm -rf /tmp/Python-${PYTHON_VERSION}

# Setup Poetry in its own virtual environment.
# So when poetry changes the system dependencies, it doesn't uninstall itself.
ENV POETRY_HOME "/opt/poetry"
RUN python3 -m venv $POETRY_HOME
RUN $POETRY_HOME/bin/pip install poetry==1.8.3
RUN ln -s $POETRY_HOME/bin/poetry /usr/local/bin/poetry

# Install Docker.
# Pin the version to an older one due to gVisor incompatibilities.
# See https://github.com/google/osv.dev/issues/1019#issuecomment-1427418758
ARG DOCKER_VERSION=5:20.10.22~3-0~ubuntu-bionic
RUN curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/trusted.gpg.d/docker.gpg && \
    add-apt-repository \
    "deb [arch=amd64] https://download.docker.com/linux/ubuntu bionic stable" && \
    apt-get install -y docker-ce=$DOCKER_VERSION docker-ce-cli=$DOCKER_VERSION && \
    apt-mark hold docker-ce docker-ce-cli  # Prevent subsequent upgrades from bumping the version.

# Install gcloud
RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] http://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && \
    curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg && \
    apt-get update && apt-get install -y google-cloud-sdk

# Install gVisor.
RUN curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor -o /etc/apt/trusted.gpg.d/gvisor.gpg && \
    # Pinning the version as the latest has a hash sum mismatch.
    add-apt-repository "deb https://storage.googleapis.com/gvisor/releases 20220621 main" && \
    apt-get update && apt-get install -y runsc

# Make gVisor the default Docker runtime.
COPY docker/worker/daemon.json /etc/docker/daemon.json

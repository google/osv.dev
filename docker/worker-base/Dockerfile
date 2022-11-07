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

RUN curl -sS https://www.python.org/ftp/python/3.11.0/Python-3.11.0.tgz | tar -C /tmp -xzv && \
    cd /tmp/Python-3.11.0 && \
    ./configure --enable-optimizations --with-lto --enable-loadable-sqlite-extensions && \
    make && \
    make install && \
    rm -rf /tmp/Python-3.11.0
RUN pip3 install pipenv

# Install Docker.
RUN curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add - && \
    add-apt-repository \
        "deb [arch=amd64] https://download.docker.com/linux/ubuntu bionic stable" && \
    apt-get install -y docker-ce

# Install gcloud
RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] http://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && \
    curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg add - && \
    apt-get update && apt-get install -y google-cloud-sdk

# Install gVisor.
RUN curl -fsSL https://gvisor.dev/archive.key | apt-key add - && \
    # Pinning the version as the latest has a hash sum mismatch.
    add-apt-repository "deb https://storage.googleapis.com/gvisor/releases 20220621 main" && \
    apt-get update && apt-get install -y runsc

# Make gVisor the default Docker runtime.
COPY docker/worker/daemon.json /etc/docker/daemon.json
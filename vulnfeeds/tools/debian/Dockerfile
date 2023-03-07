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

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y \
    apt-transport-https \
    ca-certificates \
    curl \
    git \
    gnupg-agent \
    golang-go \
    software-properties-common \
    python3 \
    python3-pip

RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && \
    curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg add - && \
    apt-get update && apt-get install -y google-cloud-sdk

RUN pip install pipenv==2022.11.5

RUN mkdir /src
WORKDIR /src

ENV PIP_NO_BINARY ""
COPY . /src

ENV LANG en_US.UTF-8
RUN cd debian_converter && pipenv install --deploy

RUN chmod +x /src/run_*

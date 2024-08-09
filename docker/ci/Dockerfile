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

FROM gcr.io/oss-vdb/worker

RUN apt-get update && \
    apt-get install -y \
    wget \
    google-cloud-sdk-datastore-emulator \
    openjdk-11-jre  # Needed for Datastore emulator.

COPY daemon.json /etc/docker/daemon.json
COPY install_go.sh /tmp/install_go.sh

RUN "/tmp/install_go.sh"
ENV PATH "$PATH:/root/.go/bin:/root/go/bin"

RUN go install -tags extended github.com/gohugoio/hugo@v0.111.3

# Set virtualenv back to false to run the tests, so each test has its
# own virtualenvs.
RUN poetry config virtualenvs.create true

ENTRYPOINT []

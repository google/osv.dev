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

FROM golang:1.24.2-alpine@sha256:7772cb5322baa875edd74705556d08f0eeca7b9c4b5367754ce3f2f00041ccee AS GO_BUILD

RUN mkdir /src
WORKDIR /src

COPY ./go.mod /src/go.mod
COPY ./go.sum /src/go.sum
RUN go mod download

COPY ./ /src/
RUN go build -o debian-osv ./cmd/debian/


FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine@sha256:60571bf8e55f8dee8d6e457b4b4344e424b308456649ff2a9fbf91816c0b31e9

WORKDIR /root/
COPY --from=GO_BUILD /src/debian-osv ./
COPY ./cmd/debian/run_debian_convert.sh ./

RUN chmod 755 ./run_debian_convert.sh

ENTRYPOINT ["/root/run_debian_convert.sh"]

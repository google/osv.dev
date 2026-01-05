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

FROM golang:1.25.5-alpine@sha256:26111811bc967321e7b6f852e914d14bede324cd1accb7f81811929a6a57fea9 AS GO_BUILD

RUN mkdir /src
WORKDIR /src

COPY ./go.mod /src/go.mod
COPY ./go.sum /src/go.sum
RUN go mod download

COPY ./ /src/
RUN go build -o download-cves ./cmd/download-cves/

FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine@sha256:09ca9257eea270001fdb49b0b176c0e3018c6858d83e085835c1ef700a457a5d

WORKDIR /usr/local/bin
COPY --from=GO_BUILD /src/download-cves ./
COPY ./cmd/download-cves/mirror_nvd.sh ./

ENTRYPOINT ["/usr/local/bin/mirror_nvd.sh"]

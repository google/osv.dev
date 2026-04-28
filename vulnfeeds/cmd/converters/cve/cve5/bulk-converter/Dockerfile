# Copyright 2025 Google LLC
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

FROM golang:1.26.2-alpine@sha256:f85330846cde1e57ca9ec309382da3b8e6ae3ab943d2739500e08c86393a21b1 AS go_build

RUN mkdir /src
WORKDIR /src

COPY ./go.mod /src/go.mod
COPY ./go.sum /src/go.sum
RUN go mod download && go mod verify


COPY ./ /src/
RUN go build -o cve-bulk-converter ./cmd/converters/cve/cve5/bulk-converter/

FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine@sha256:30b3a542786ee597ddc866aaf1d5201e794be1a4c328507a0531b97ad469ea64
RUN apk --no-cache add jq

WORKDIR /root/
COPY --from=go_build /src/cve-bulk-converter ./
COPY ./cmd/converters/cve/cve5/bulk-converter/run-cvelist-converter.sh ./

ENTRYPOINT ["/root/run-cvelist-converter.sh"]

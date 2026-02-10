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

FROM golang:1.25.7-alpine@sha256:81d49e1de26fa223b9ae0b4d5a4065ff8176a7d80aa5ef0bd9f2eee430afe4d7 AS go_build

RUN mkdir /src
WORKDIR /src

COPY ./go.mod /src/go.mod
COPY ./go.sum /src/go.sum
RUN go mod download && go mod verify


COPY ./ /src/
RUN go build -o cve-bulk-converter ./cmd/converters/cve/cve5/bulk-converter/

FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine@sha256:68100018e78bc098b4dc04a95416edd3ad6a3c7bb5947531b4747176953918f8
RUN apk --no-cache add jq

WORKDIR /root/
COPY --from=go_build /src/cve-bulk-converter ./
COPY ./cmd/converters/cve/cve5/bulk-converter/run-cvelist-converter.sh ./

ENTRYPOINT ["/root/run-cvelist-converter.sh"]

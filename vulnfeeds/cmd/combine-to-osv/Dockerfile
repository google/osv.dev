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

FROM golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS GO_BUILD

RUN mkdir /src
WORKDIR /src

COPY ./go.mod /src/go.mod
COPY ./go.sum /src/go.sum
RUN go mod download

COPY ./ /src/
RUN go build -o combine-to-osv ./cmd/combine-to-osv/
RUN go build -o download-cves ./cmd/mirrors/download-cves/


FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine@sha256:3b058be4e039dd710f42c9e471e43443b632eee3c9111660a85a399c13fa153f
RUN apk --no-cache add jq

WORKDIR /root/
COPY --from=GO_BUILD /src/combine-to-osv ./
COPY --from=GO_BUILD /src/download-cves ./
COPY ./cmd/combine-to-osv/run_combine_to_osv_convert.sh ./

ENTRYPOINT ["/root/run_combine_to_osv_convert.sh"]

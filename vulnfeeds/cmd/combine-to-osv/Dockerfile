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

FROM golang:1.24.6-alpine@sha256:c8c5f95d64aa79b6547f3b626eb84b16a7ce18a139e3e9ca19a8c078b85ba80d AS GO_BUILD

RUN mkdir /src
WORKDIR /src

COPY ./go.mod /src/go.mod
COPY ./go.sum /src/go.sum
RUN go mod download

COPY ./ /src/
RUN go build -o combine-to-osv ./cmd/combine-to-osv/
RUN go build -o download-cves ./cmd/download-cves/


FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine@sha256:dcd2fe363cc8bd1969bccb41add5b7b008c56927c957f4e56c9686986e28e863
RUN apk --no-cache add jq

WORKDIR /root/
COPY --from=GO_BUILD /src/combine-to-osv ./
COPY --from=GO_BUILD /src/download-cves ./
COPY ./cmd/combine-to-osv/run_combine_to_osv_convert.sh ./

ENTRYPOINT ["/root/run_combine_to_osv_convert.sh"]

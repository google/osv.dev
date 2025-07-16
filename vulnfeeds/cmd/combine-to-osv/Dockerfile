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

FROM golang:1.24.5-alpine@sha256:9c4b616be9d26e4762219223331bab5db98649e4be1f6badeac3f7c00a340e3f AS GO_BUILD

RUN mkdir /src
WORKDIR /src

COPY ./go.mod /src/go.mod
COPY ./go.sum /src/go.sum
RUN go mod download

COPY ./ /src/
RUN go build -o combine-to-osv ./cmd/combine-to-osv/
RUN go build -o download-cves ./cmd/download-cves/


FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine@sha256:8ce775825f971fea637196751861bdea40f33d94b5e025214510f51996699343
RUN apk --no-cache add jq

WORKDIR /root/
COPY --from=GO_BUILD /src/combine-to-osv ./
COPY --from=GO_BUILD /src/download-cves ./
COPY ./cmd/combine-to-osv/run_combine_to_osv_convert.sh ./

ENTRYPOINT ["/root/run_combine_to_osv_convert.sh"]

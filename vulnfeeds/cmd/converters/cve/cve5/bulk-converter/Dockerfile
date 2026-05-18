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

FROM golang:1.26.3-alpine@sha256:91eda9776261207ea25fd06b5b7fed8d397dd2c0a283e77f2ab6e91bfa71079d AS go_build

RUN mkdir /src
WORKDIR /src

COPY ./go.mod /src/go.mod
COPY ./go.sum /src/go.sum
RUN go mod download && go mod verify


COPY ./ /src/
RUN go build -o cve-bulk-converter ./cmd/converters/cve/cve5/bulk-converter/

FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine@sha256:36d52526dfdfc696f4f7e53251c05377e336b81c310c00dd8cfb87b5bf03baeb
RUN apk --no-cache add jq

WORKDIR /root/
COPY --from=go_build /src/cve-bulk-converter ./
COPY ./cmd/converters/cve/cve5/bulk-converter/run-cvelist-converter.sh ./

ENTRYPOINT ["/root/run-cvelist-converter.sh"]

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

FROM golang:1.24.5-alpine@sha256:daae04ebad0c21149979cd8e9db38f565ecefd8547cf4a591240dc1972cf1399 AS GO_BUILD

RUN mkdir /src
WORKDIR /src

COPY ./go.mod /src/go.mod
COPY ./go.sum /src/go.sum
RUN go mod download

COPY ./ /src/
RUN go build -o download-cves ./cmd/download-cves/

FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine@sha256:fccf0b0dcfd5a0437887abf0b2f99e9331f441a9e9512213ac6fe8902b53c7ab
RUN apk --no-cache add jq

WORKDIR /usr/local/bin
COPY --from=GO_BUILD /src/download-cves ./
COPY ./cmd/download-cves/mirror_nvd.sh ./

ENTRYPOINT ["/usr/local/bin/mirror_nvd.sh"]

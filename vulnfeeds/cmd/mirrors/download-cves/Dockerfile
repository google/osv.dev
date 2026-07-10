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

FROM golang:1.26.4-alpine@sha256:f23e8b227fb4493eabe03bede4d5a32d04092da71962f1fb79b5f7d1e6c2a17f AS GO_BUILD

RUN mkdir /src
WORKDIR /src

COPY ./go.mod /src/go.mod
COPY ./go.sum /src/go.sum
RUN go mod download

COPY ./ /src/
RUN go build -o download-cves ./cmd/mirrors/download-cves/

FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine@sha256:1f97bc805d9e957f1e0428d3f2db0c5e710e72fcb83d60bbc6d3506f082fe331

WORKDIR /usr/local/bin
COPY --from=GO_BUILD /src/download-cves ./
COPY ./cmd/mirrors/download-cves/mirror_nvd.sh ./

ENTRYPOINT ["/usr/local/bin/mirror_nvd.sh"]

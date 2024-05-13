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

FROM golang:1.22.3-alpine@sha256:2a882244fb51835ebbd8313bffee83775b0c076aaf56b497b43d8a4c72db65e1 AS GO_BUILD

RUN mkdir /src
WORKDIR /src

COPY ./go.mod /src/go.mod
COPY ./go.sum /src/go.sum
RUN go mod download

COPY ./ /src/
RUN CGO_ENABLED=0 go build -o cpe-repo-gen ./cmd/cpe-repo-gen

FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine

COPY --from=GO_BUILD /src/cpe-repo-gen ./
COPY ./cmd/cpe-repo-gen/cpe-repo-gen_map.sh ./

ENTRYPOINT ["/cpe-repo-gen_map.sh"]

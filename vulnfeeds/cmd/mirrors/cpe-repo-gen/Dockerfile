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

FROM golang:1.26.1-alpine@sha256:2389ebfa5b7f43eeafbd6be0c3700cc46690ef842ad962f6c5bd6be49ed82039 AS GO_BUILD

RUN mkdir /src
WORKDIR /src

COPY ./go.mod /src/go.mod
COPY ./go.sum /src/go.sum
RUN go mod download

COPY ./ /src/
RUN CGO_ENABLED=0 go build -o cpe-repo-gen ./cmd/mirrors/cpe-repo-gen

FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine@sha256:dae004fbcf8af0a19e4aa2788bac2be8f65cf205c337815c7465a5e880948263

RUN apk add --no-cache unzip

COPY --from=GO_BUILD /src/cpe-repo-gen ./
COPY ./cmd/mirrors/cpe-repo-gen/cpe-repo-gen_map.sh ./

ENTRYPOINT ["/cpe-repo-gen_map.sh"]

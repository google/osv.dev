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

FROM golang:1.27.1-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS GO_BUILD

RUN mkdir /src
WORKDIR /src

COPY ./go.mod /src/go.mod
COPY ./go.sum /src/go.sum
RUN go mod download

COPY ./ /src/
RUN CGO_ENABLED=0 go build -o cpe-repo-gen ./cmd/mirrors/cpe-repo-gen

FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine@sha256:9040d28a6512f32c495322a3af6ea000f803a0ae001cec055937154efe5a2230

RUN apk add --no-cache unzip

COPY --from=GO_BUILD /src/cpe-repo-gen ./
COPY ./cmd/mirrors/cpe-repo-gen/cpe-repo-gen_map.sh ./

ENTRYPOINT ["/cpe-repo-gen_map.sh"]

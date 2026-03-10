# Copyright 2026 Google LLC
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

FROM golang:1.26.1-alpine@sha256:d337ecb3075f0ec76d81652b3fa52af47c3eba6c8ba9f93b835752df7ce62946 AS build

WORKDIR /src

COPY ./go.mod /src/go.mod
COPY ./go.sum /src/go.sum
RUN go mod download && go mod verify


COPY ./ /src/
RUN CGO_ENABLED=0 go build -o importer ./cmd/importer/

FROM alpine:3.23@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659

# Need to install the full tar package, to not use the busybox version, which doesn't have --zstd support.
RUN apk add --no-cache git zstd tar

COPY --from=build /src/importer /

ENTRYPOINT ["/importer"]

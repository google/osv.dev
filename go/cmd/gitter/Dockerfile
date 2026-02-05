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

FROM golang:1.25.7-alpine@sha256:81d49e1de26fa223b9ae0b4d5a4065ff8176a7d80aa5ef0bd9f2eee430afe4d7 AS build

WORKDIR /src

COPY ./go.mod /src/go.mod
COPY ./go.sum /src/go.sum
RUN go mod download && go mod verify


COPY ./ /src/
RUN CGO_ENABLED=0 go build -o gitter ./cmd/gitter/

FROM alpine:3.23@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659

# Need to install the full tar package, to not use the busybox version, which doesn't have --zstd support.
RUN apk add --no-cache git zstd tar

COPY --from=build /src/gitter /

ENTRYPOINT ["/gitter"]

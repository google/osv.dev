#!/bin/bash -e

# Copyright 2022 OSV Schema Authors
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

FROM golang:1.26.2-alpine@sha256:c2a1f7b2095d046ae14b286b18413a05bb82c9bca9b25fe7ff5efef0f0826166 AS build

WORKDIR /src

COPY ./go.mod /src/go.mod
COPY ./go.sum /src/go.sum
RUN go mod download && go mod verify

COPY ./ /src/
RUN CGO_ENABLED=0 go build -o dsa-dla-dtsa ./cmd/converters/dsa-dla-dtsa/main.go

FROM alpine:3.23@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659
RUN apk add --no-cache git ca-certificates
# Increase the Git buffer to 500MB and disable compression to prevent timeouts
# downgrading http to 1.1 seems to be the only thing that works
# TODO: revise this
RUN git config --global http.postBuffer 524288000 \
    && git config --global http.maxRequestBuffer 100M \
    && git config --global core.compression 0 \
    && git config --global http.version HTTP/1.1
WORKDIR /src
COPY --from=build /src/dsa-dla-dtsa ./dsa-dla-dtsa

ENTRYPOINT ["./dsa-dla-dtsa"]


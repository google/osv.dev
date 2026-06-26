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

FROM golang:1.26.4-alpine@sha256:3ad57304ad93bbec8548a0437ad9e06a455660655d9af011d58b993f6f615648 AS build

WORKDIR /src

COPY ./go.mod /src/go.mod
COPY ./go.sum /src/go.sum
RUN go mod download && go mod verify

COPY ./ /src/
RUN CGO_ENABLED=0 go build -o dsa-dla-dtsa ./cmd/converters/dsa-dla-dtsa/main.go

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
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


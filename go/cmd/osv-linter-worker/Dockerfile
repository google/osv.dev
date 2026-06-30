# syntax=docker/dockerfile:1
# Copyright 2024 Google LLC
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


# Stage 1: Build the Go linter binary
FROM golang:1.26.4-alpine@sha256:3ad57304ad93bbec8548a0437ad9e06a455660655d9af011d58b993f6f615648 AS go_builder

RUN apk add --no-cache git
WORKDIR /src

# Using osv-schema v1.7.3+
RUN git clone https://github.com/ossf/osv-schema.git osv-schema && cd osv-schema && git checkout 447c7315b34e7f565538c667b532586ca76efe10

WORKDIR /src/osv-schema/tools/osv-linter

RUN go mod download

RUN go generate ./...

RUN CGO_ENABLED=0 GOOS=linux go build -o /usr/local/bin/osv-linter ./cmd/osv

# Build the worker binary
COPY --from=bindings . /src/osv.dev/bindings/
WORKDIR /src/osv.dev/go
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /usr/local/bin/osv-linter-worker ./cmd/osv-linter-worker

# Stage 2: Run worker
FROM gcr.io/oss-vdb/worker

# Copy the built Go binaries from the 'go_builder' stage
COPY --from=go_builder /usr/local/bin/osv-linter /usr/local/bin/osv-linter
COPY --from=go_builder /usr/local/bin/osv-linter-worker /usr/local/bin/osv-linter-worker

WORKDIR /linter

ENTRYPOINT ["osv-linter-worker"]

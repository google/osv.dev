# syntax=docker/dockerfile:1
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

# ====================================================================================
# HOW TO BUILD THIS DOCKERFILE LOCALLY:
# 
# Because go/go.mod contains a relative replacement directive for bindings/go, 
# you must build this Dockerfile from the go/ directory and explicitly map 
# the sibling bindings/ folder in BuildKit using --build-context:
# 
#   cd go
#   docker build -t osv/importer --target importer --build-context bindings=../bindings -f Dockerfile .
# 
# Select which service to build using the --target flag (e.g. importer, worker, exporter, 
# relations, recordchecker, generatesitemap, custommetrics, gitter, first_package_finder, api).
# ====================================================================================

# ========================================================
# Shared Builder Stage
# ========================================================
FROM golang:1.26.4-alpine@sha256:3ad57304ad93bbec8548a0437ad9e06a455660655d9af011d58b993f6f615648 AS builder

WORKDIR /workspace

# Mount the 'bindings' context into the container's filesystem
COPY --from=bindings . /workspace/bindings/

# Copy the main Go module (strictly go/)
COPY . /workspace/go/

WORKDIR /workspace/go
RUN go mod download && go mod verify

# ========================================================
# Target: Importer
# ========================================================
FROM builder AS importer-build
RUN CGO_ENABLED=0 go build -o /app/importer ./cmd/importer/

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS importer
# Need to install the full tar package, to not use the busybox version, which doesn't have --zstd support.
RUN apk add --no-cache git zstd tar
COPY --from=importer-build /app/importer /
ENTRYPOINT ["/importer"]

# ========================================================
# Target: Worker
# ========================================================
FROM builder AS worker-build
RUN CGO_ENABLED=0 go build -o /app/worker ./cmd/worker/

FROM gcr.io/distroless/static-debian12@sha256:9c346e4be81b5ca7ff31a0d89eaeade58b0f95cfd3baed1f36083ddb47ca3160 AS worker
COPY --from=worker-build /app/worker /
ENTRYPOINT ["/worker"]

# ========================================================
# Target: Exporter
# ========================================================
FROM builder AS exporter-build
RUN CGO_ENABLED=0 go build -o /app/exporter ./cmd/exporter/

FROM gcr.io/distroless/static-debian12@sha256:9c346e4be81b5ca7ff31a0d89eaeade58b0f95cfd3baed1f36083ddb47ca3160 AS exporter
COPY --from=exporter-build /app/exporter /
ENTRYPOINT ["/exporter"]

# ========================================================
# Target: Record Checker
# ========================================================
FROM builder AS recordchecker-build
RUN CGO_ENABLED=0 go build -o /app/recordchecker ./cmd/recordchecker/

FROM gcr.io/distroless/static-debian12@sha256:9c346e4be81b5ca7ff31a0d89eaeade58b0f95cfd3baed1f36083ddb47ca3160 AS recordchecker
COPY --from=recordchecker-build /app/recordchecker /
ENTRYPOINT ["/recordchecker"]

# ========================================================
# Target: Relations
# ========================================================
FROM builder AS relations-build
RUN CGO_ENABLED=0 go build -o /app/relations ./cmd/relations/

FROM gcr.io/distroless/static-debian12@sha256:9c346e4be81b5ca7ff31a0d89eaeade58b0f95cfd3baed1f36083ddb47ca3160 AS relations
COPY --from=relations-build /app/relations /
ENTRYPOINT ["/relations"]

# ========================================================
# Target: Generate Sitemap
# ========================================================
FROM builder AS generatesitemap-build
RUN CGO_ENABLED=0 go build -o /app/generatesitemap ./cmd/generatesitemap/

FROM gcr.io/distroless/static-debian12@sha256:9c346e4be81b5ca7ff31a0d89eaeade58b0f95cfd3baed1f36083ddb47ca3160 AS generatesitemap
COPY --from=generatesitemap-build /app/generatesitemap /
ENTRYPOINT ["/generatesitemap"]

# ========================================================
# Target: Custom Metrics
# ========================================================
FROM builder AS custommetrics-build
RUN CGO_ENABLED=0 go build -o /app/custommetrics ./cmd/custommetrics/

FROM gcr.io/distroless/static-debian12@sha256:9c346e4be81b5ca7ff31a0d89eaeade58b0f95cfd3baed1f36083ddb47ca3160 AS custommetrics
COPY --from=custommetrics-build /app/custommetrics /
ENTRYPOINT ["/custommetrics"]

# ========================================================
# Target: Gitter
# ========================================================
FROM builder AS gitter-build
RUN CGO_ENABLED=0 go build -o /app/gitter ./cmd/gitter/

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS gitter
# Need to install the full tar package, to not use the busybox version, which doesn't have --zstd support.
RUN apk add --no-cache bash git zstd tar
# Set maintenance.autoDetach to false so git's automatic maintenance will not detach and run in the background
RUN git config --system maintenance.autoDetach false
COPY --from=gitter-build /app/gitter /
ENTRYPOINT ["/gitter"]

# ========================================================
# Target: First Package Finder
# ========================================================
FROM builder AS first_package_finder-build
RUN CGO_ENABLED=0 go build -o /app/first_package_finder ./cmd/first_package_finder/

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS first_package_finder
COPY --from=first_package_finder-build /app/first_package_finder /
ENTRYPOINT ["/first_package_finder"]

# ========================================================
# Target: OSV API
# ========================================================
FROM builder AS api-build
RUN CGO_ENABLED=0 go build -o /app/api ./cmd/api/

FROM gcr.io/distroless/static-debian12@sha256:9c346e4be81b5ca7ff31a0d89eaeade58b0f95cfd3baed1f36083ddb47ca3160 AS api
COPY --from=api-build /app/api /
ENTRYPOINT ["/api"]

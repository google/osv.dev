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
# Unified Multi-Target Dockerfile for Vulnfeeds Services
#
# Usage (from the vulnfeeds/ directory):
#   docker build --target <service_name> -f Dockerfile .
#
# Targets:
#   alpine-cve-convert, debian-cve-convert, combine-to-osv, cve5-to-osv,
#   debian-convert, debian-copyright-mirror, cpe-repo-gen, nvd-cve-osv, nvd-mirror
# ====================================================================================

# ========================================================
# Shared Builder & Runtime Base Stages
# ========================================================
FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS builder
# Cap compile-time Go parallelism to avoid CPU/RAM oversubscription when multiple
# targets build concurrently on E2_HIGHCPU_32 (32 vCPU / 32 GB RAM).
ENV GOMAXPROCS=8

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download && go mod verify

COPY . /src/

FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine@sha256:31e27958892650f753ecf6fab1c4aebc4f0bfdc55c6364da8902c62b852791cf AS gcloud-alpine

FROM gcloud-alpine AS gcloud-alpine-jq
RUN apk --no-cache add jq

# ========================================================
# Target: Alpine CVE Convert
# ========================================================
FROM builder AS alpine-cve-convert-build
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -o /app/alpine-osv ./cmd/converters/alpine/

FROM gcloud-alpine AS alpine-cve-convert
WORKDIR /root/
COPY --from=alpine-cve-convert-build /app/alpine-osv ./
COPY ./cmd/converters/alpine/run_alpine_convert.sh ./
ENTRYPOINT ["/root/run_alpine_convert.sh"]

# ========================================================
# Target: Debian CVE Convert
# ========================================================
FROM builder AS debian-cve-convert-build
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -o /app/debian ./cmd/converters/debian/

FROM gcloud-alpine AS debian-cve-convert
WORKDIR /root/
COPY --from=debian-cve-convert-build /app/debian ./
ENTRYPOINT ["/root/debian"]

# ========================================================
# Target: Combine to OSV
# ========================================================
FROM builder AS combine-to-osv-build
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -o /app/combine-to-osv ./cmd/combine-to-osv/ && \
    CGO_ENABLED=0 go build -o /app/download-cves ./cmd/mirrors/download-cves/

FROM gcloud-alpine-jq AS combine-to-osv
WORKDIR /root/
COPY --from=combine-to-osv-build /app/combine-to-osv ./
COPY --from=combine-to-osv-build /app/download-cves ./
COPY ./cmd/combine-to-osv/run_combine_to_osv_convert.sh ./
ENTRYPOINT ["/root/run_combine_to_osv_convert.sh"]

# ========================================================
# Target: CVE5 to OSV
# ========================================================
FROM builder AS cve5-to-osv-build
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -o /app/cve-bulk-converter ./cmd/converters/cve/cve5/bulk-converter/

FROM gcloud-alpine-jq AS cve5-to-osv
WORKDIR /root/
COPY --from=cve5-to-osv-build /app/cve-bulk-converter ./
COPY ./cmd/converters/cve/cve5/bulk-converter/run-cvelist-converter.sh ./
ENTRYPOINT ["/root/run-cvelist-converter.sh"]

# ========================================================
# Target: Debian Convert (DSA/DLA/DTSA)
# ========================================================
FROM builder AS debian-convert-build
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -o /app/dsa-dla-dtsa ./cmd/converters/dsa-dla-dtsa/main.go

FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS debian-convert
RUN apk add --no-cache "git>=2.54.1" ca-certificates
# Increase the Git buffer to 500MB and disable compression to prevent timeouts
# downgrading http to 1.1 seems to be the only thing that works
# TODO: revise this
RUN git config --global http.postBuffer 524288000 \
    && git config --global http.maxRequestBuffer 100M \
    && git config --global core.compression 0 \
    && git config --global http.version HTTP/1.1
WORKDIR /src
COPY --from=debian-convert-build /app/dsa-dla-dtsa ./dsa-dla-dtsa
ENTRYPOINT ["./dsa-dla-dtsa"]

# ========================================================
# Target: Debian Copyright Mirror
# ========================================================
FROM builder AS debian-copyright-mirror-build
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -o /app/debian-copyright-mirror ./cmd/mirrors/debian-copyright-mirror

FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS debian-copyright-mirror
RUN apk add --no-cache xz curl tar ca-certificates
COPY --from=debian-copyright-mirror-build /app/debian-copyright-mirror /usr/local/bin/debian-copyright-mirror
ENTRYPOINT ["/usr/local/bin/debian-copyright-mirror"]

# ========================================================
# Target: CPE Repo Gen
# ========================================================
FROM builder AS cpe-repo-gen-build
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -o /app/cpe-repo-gen ./cmd/mirrors/cpe-repo-gen

FROM gcloud-alpine AS cpe-repo-gen
RUN apk add --no-cache unzip
COPY --from=cpe-repo-gen-build /app/cpe-repo-gen ./
COPY ./cmd/mirrors/cpe-repo-gen/cpe-repo-gen_map.sh ./
ENTRYPOINT ["/cpe-repo-gen_map.sh"]

# ========================================================
# Target: NVD CVE to OSV
# ========================================================
FROM builder AS nvd-cve-osv-build
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -o /app/ ./cmd/converters/cve/nvd-cve-osv ./cmd/mirrors/download-cves

FROM gcloud-alpine-jq AS nvd-cve-osv
COPY --from=nvd-cve-osv-build /app/ /usr/local/bin/
COPY ./cmd/converters/cve/nvd-cve-osv/run_cve_to_osv_generation.sh /usr/local/bin/
CMD ["/usr/local/bin/run_cve_to_osv_generation.sh"]

# ========================================================
# Target: NVD Mirror
# ========================================================
FROM builder AS nvd-mirror-build
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -o /app/download-cves ./cmd/mirrors/download-cves/

FROM gcloud-alpine AS nvd-mirror
WORKDIR /usr/local/bin
COPY --from=nvd-mirror-build /app/download-cves ./
ENTRYPOINT ["/usr/local/bin/download-cves"]

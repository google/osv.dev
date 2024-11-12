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

FROM golang:1.23.2-alpine@sha256:9dd2625a1ff2859b8d8b01d8f7822c0f528942fe56cfe7a1e7c38d3b8d72d679 AS GO_BUILD
WORKDIR /build

# Cache dependencies in these steps
COPY ./go.mod /build/go.mod
COPY ./go.sum /build/go.sum
RUN go mod download

# Do the build here
COPY ./ /build
RUN CGO_ENABLED=0 ./build.sh

FROM gcr.io/distroless/base-debian12@sha256:7a4bffcb07307d97aa731b50cb6ab22a68a8314426f4e4428335939b5b1943a5
COPY --from=GO_BUILD build/indexer /indexer
ENTRYPOINT ["/indexer"]
CMD ["--help"]

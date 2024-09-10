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

FROM golang:1.23.1-alpine@sha256:ac67716dd016429be8d4c2c53a248d7bcdf06d34127d3dc451bda6aa5a87bc06 AS GO_BUILD
WORKDIR /build

# Cache dependencies in these steps
COPY ./go.mod /build/go.mod
COPY ./go.sum /build/go.sum
RUN go mod download

# Do the build here
COPY ./ /build
RUN CGO_ENABLED=0 ./build.sh

FROM gcr.io/distroless/base-debian12@sha256:c925d12234f8d3fbef2256012b168004d4c47a82c4f06afcfd06fd208732fbe0
COPY --from=GO_BUILD build/indexer /indexer
ENTRYPOINT ["/indexer"]
CMD ["--help"]

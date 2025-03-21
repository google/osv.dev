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

FROM golang:1.24.1-alpine@sha256:43c094ad24b6ac0546c62193baeb3e6e49ce14d3250845d166c77c25f64b0386 AS GO_BUILD
WORKDIR /build

# Cache dependencies in these steps
COPY ./go.mod /build/go.mod
COPY ./go.sum /build/go.sum
RUN go mod download

# Do the build here
COPY ./ /build
RUN CGO_ENABLED=0 ./build.sh

FROM gcr.io/distroless/base-debian12@sha256:125eb09bbd8e818da4f9eac0dfc373892ca75bec4630aa642d315ecf35c1afb7
COPY --from=GO_BUILD build/indexer /indexer
ENTRYPOINT ["/indexer"]
CMD ["--help"]

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

FROM golang:1.26.4-alpine@sha256:f23e8b227fb4493eabe03bede4d5a32d04092da71962f1fb79b5f7d1e6c2a17f AS GO_BUILD
WORKDIR /build

# Cache dependencies in these steps
COPY ./go.mod /build/go.mod
COPY ./go.sum /build/go.sum
RUN go mod download

# Do the build here
COPY ./ /build
RUN CGO_ENABLED=0 ./build.sh

FROM gcr.io/distroless/base-debian12@sha256:58695f439f772a00009c8f6be4c183f824c1f556d74b313c30900f167e4772f8
COPY --from=GO_BUILD build/indexer /indexer
ENTRYPOINT ["/indexer"]
CMD ["--help"]

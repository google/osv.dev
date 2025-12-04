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

FROM golang:1.25.4-alpine@sha256:d3f0cf7723f3429e3f9ed846243970b20a2de7bae6a5b66fc5914e228d831bbb AS build

WORKDIR /src

COPY ./go.mod /src/go.mod
COPY ./go.sum /src/go.sum
RUN go mod download && go mod verify


COPY ./ /src/
RUN CGO_ENABLED=0 go build -o relations ./cmd/relations

FROM gcr.io/distroless/static-debian12@sha256:87bce11be0af225e4ca761c40babb06d6d559f5767fbf7dc3c47f0f1a466b92c

COPY --from=build /src/relations /

ENTRYPOINT ["/relations"]

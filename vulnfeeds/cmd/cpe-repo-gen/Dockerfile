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

FROM golang:1.24.4-alpine@sha256:68932fa6d4d4059845c8f40ad7e654e626f3ebd3706eef7846f319293ab5cb7a AS GO_BUILD

RUN mkdir /src
WORKDIR /src

COPY ./go.mod /src/go.mod
COPY ./go.sum /src/go.sum
RUN go mod download

COPY ./ /src/
RUN CGO_ENABLED=0 go build -o cpe-repo-gen ./cmd/cpe-repo-gen

FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine@sha256:f0f43981a0b69a5d6390a1e9cc47e2355a873e1c1e9d6d1b923cbded92bda671

COPY --from=GO_BUILD /src/cpe-repo-gen ./
COPY ./cmd/cpe-repo-gen/cpe-repo-gen_map.sh ./

ENTRYPOINT ["/cpe-repo-gen_map.sh"]

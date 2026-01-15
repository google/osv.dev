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

FROM golang:1.25.5-alpine@sha256:ac09a5f469f307e5da71e766b0bd59c9c49ea460a528cc3e6686513d64a6f1fb AS GO_BUILD

RUN mkdir /src
WORKDIR /src

COPY ./go.mod /src/go.mod
COPY ./go.sum /src/go.sum
RUN go mod download

COPY ./ /src/
RUN go build -o debian ./cmd/debian/


FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine@sha256:feca5d4cb9b422e124e6f28b8ed2e714160757eb383eaae712117c75f584aa2f

WORKDIR /root/
COPY --from=GO_BUILD /src/debian ./
COPY ./cmd/debian/run_debian_convert.sh ./

RUN chmod 755 ./run_debian_convert.sh

ENTRYPOINT ["/root/run_debian_convert.sh"]

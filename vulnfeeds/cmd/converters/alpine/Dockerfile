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

FROM golang:1.27.3-alpine@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 AS GO_BUILD

RUN mkdir /src
WORKDIR /src

COPY ./go.mod /src/go.mod
COPY ./go.sum /src/go.sum
RUN go mod download

COPY ./ /src/
RUN go build -o alpine-osv ./cmd/converters/alpine/


FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine@sha256:269c3ae5175a900ea6be98322dcc65d4cb1499ec9f8f262d19bbd128c6a898c8

WORKDIR /root/
COPY --from=GO_BUILD /src/alpine-osv ./
COPY ./cmd/converters/alpine/run_alpine_convert.sh ./

ENTRYPOINT ["/root/run_alpine_convert.sh"]

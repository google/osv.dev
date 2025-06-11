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
RUN go build -o alpine-osv ./cmd/alpine/


FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine@sha256:ca70dd0fcf3924c9b05527b55fe0cc08eff55bc970941101fcf28041a3a08e69

WORKDIR /root/
COPY --from=GO_BUILD /src/alpine-osv ./
COPY ./cmd/alpine/run_alpine_convert.sh ./

ENTRYPOINT ["/root/run_alpine_convert.sh"]

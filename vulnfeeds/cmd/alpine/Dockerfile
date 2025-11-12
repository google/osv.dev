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

FROM golang:1.25.3-alpine@sha256:aee43c3ccbf24fdffb7295693b6e33b21e01baec1b2a55acc351fde345e9ec34 AS GO_BUILD

RUN mkdir /src
WORKDIR /src

COPY ./go.mod /src/go.mod
COPY ./go.sum /src/go.sum
RUN go mod download

COPY ./ /src/
RUN go build -o alpine-osv ./cmd/alpine/


FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine@sha256:cdac858d976cb0e6bfdc3288fee5a0a7bf6348a009089be130b2009e28463c52

WORKDIR /root/
COPY --from=GO_BUILD /src/alpine-osv ./
COPY ./cmd/alpine/run_alpine_convert.sh ./

ENTRYPOINT ["/root/run_alpine_convert.sh"]

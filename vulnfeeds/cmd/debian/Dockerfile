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

FROM golang:1.24.3-alpine@sha256:ef18ee7117463ac1055f5a370ed18b8750f01589f13ea0b48642f5792b234044 AS GO_BUILD

RUN mkdir /src
WORKDIR /src

COPY ./go.mod /src/go.mod
COPY ./go.sum /src/go.sum
RUN go mod download

COPY ./ /src/
RUN go build -o debian-osv ./cmd/debian/


FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine@sha256:0ea6aac6920cce79b2b40584e4d735fba134a275fd18ebc827cebfdadd7db1da

WORKDIR /root/
COPY --from=GO_BUILD /src/debian-osv ./
COPY ./cmd/debian/run_debian_convert.sh ./

RUN chmod 755 ./run_debian_convert.sh

ENTRYPOINT ["/root/run_debian_convert.sh"]

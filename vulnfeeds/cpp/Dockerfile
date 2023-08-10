# Copyright 2023 Google LLC
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

FROM golang:alpine@sha256:6f592e0689192b7e477313264bb190024d654ef0a08fb1732af4f4b498a2e8ad AS buildenv

WORKDIR /go/src

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .
RUN CGO_ENABLED=0 go build -v -o /usr/local/bin ./cpp ./cmd/download-cves

FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine AS runtime

COPY --from=buildenv /usr/local/bin ./usr/local/bin
COPY --from=buildenv /go/src/cpp/run_cve_to_osv_generation ./usr/local/bin

CMD ["/usr/local/bin/run_cve_to_osv_generation"]

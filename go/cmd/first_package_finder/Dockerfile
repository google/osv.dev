# Copyright 2022 Google LLC
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

FROM golang:1.24.0-alpine@sha256:2d40d4fc278dad38be0777d5e2a88a2c6dee51b0b29c97a764fc6c6a11ca893c AS GO_BUILD

RUN mkdir /src
WORKDIR /src

COPY ./go.mod /src/go.mod
COPY ./go.sum /src/go.sum
RUN go mod download

COPY ./ /src/
RUN go build -o first_package_finder_bin ./tools/debian/first_package_finder/

FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine@sha256:d2f3fd4000e4c9c641ab75898da682b771528f60f08f65e0c3a88fcdff2eaf92

WORKDIR /src
COPY --from=GO_BUILD /src/first_package_finder_bin ./first_package_finder_bin
COPY vulnfeeds/tools/debian/run_*.sh ./

RUN chmod +x ./run_*.sh

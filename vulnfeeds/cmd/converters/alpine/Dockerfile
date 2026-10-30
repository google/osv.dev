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

FROM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS GO_BUILD

RUN mkdir /src
WORKDIR /src

COPY ./go.mod /src/go.mod
COPY ./go.sum /src/go.sum
RUN go mod download

COPY ./ /src/
RUN go build -o alpine-osv ./cmd/converters/alpine/


FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine@sha256:786a1537df13c54289a46507b22a411f6c71154ae0293d12adce4b9358acca63

WORKDIR /root/
COPY --from=GO_BUILD /src/alpine-osv ./
COPY ./cmd/converters/alpine/run_alpine_convert.sh ./

ENTRYPOINT ["/root/run_alpine_convert.sh"]

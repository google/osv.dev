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


# Stage 1: Build the Go linter binary
FROM golang:1.22.6-alpine AS go_builder

RUN apk add --no-cache git
WORKDIR /src
RUN git clone https://github.com/ossf/osv-schema.git osv-schema

RUN cd osv-schema && git checkout 66427d119b39161d0f2c4448c076e5d4f625b025

WORKDIR /src/osv-schema/tools/osv-linter

RUN go mod download

RUN CGO_ENABLED=0 GOOS=linux go build -o /usr/local/bin/osv-linter ./cmd/osv

# Stage 2: Run python code
FROM gcr.io/oss-vdb/worker

# Copy the built Go binary from the 'go_builder' stage
COPY --from=go_builder /usr/local/bin/osv-linter /usr/local/bin/osv-linter

COPY linter.py /usr/local/bin

WORKDIR /linter

RUN chmod 755 /usr/local/bin/linter.py

ENTRYPOINT ["linter.py"]

# Copyright 2026 Google LLC
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

# Build context must be go/internal/database/postgres/migrations with --build-context goose=docker/goose:
#   docker buildx build --build-context goose=docker/goose -f docker/goose/migrations.Dockerfile go/internal/database/postgres/migrations
FROM gcr.io/oss-vdb/goose:latest
COPY --from=goose entrypoint.bash /builder/entrypoint.bash
RUN chmod +x /builder/entrypoint.bash
COPY *.sql /migrations/
WORKDIR /migrations

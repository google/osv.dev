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

FROM python:3.11-slim

# TODO(ochang): Just copy the entire project (needs a clean checkout).
COPY setup.py Pipfile* README.md /osv/
COPY osv /osv/osv
COPY gcp/api /osv/gcp/api

WORKDIR /osv/gcp/api
RUN pip3 install -U pipenv && python3 -m pipenv install --deploy --system

ENTRYPOINT ["python", "/osv/gcp/api/server.py"]

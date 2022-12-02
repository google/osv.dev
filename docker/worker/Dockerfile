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

ARG PROJECT=oss-vdb
FROM gcr.io/${PROJECT}/worker-base

RUN apt-get update && apt-get upgrade -y

RUN mkdir /work && mkdir -p /env/docker/worker
VOLUME /var/lib/docker

# Replicate project structure to make relative editable pipenv dependency work.
# TODO(ochang): Just copy the entire project (needs a clean checkout).
COPY docker/worker/Pipfile* /env/docker/worker/
COPY setup.py Pipfile* README.md /env/
COPY osv /env/osv
RUN cd /env/docker/worker && pip3 install pipenv && pipenv install --deploy --system

COPY docker/worker/oss_fuzz.py docker/worker/worker.py /usr/local/bin/
RUN chmod 755 /usr/local/bin/worker.py

# ARGs after a FROM are unusable without redeclaring
# See: https://docs.docker.com/engine/reference/builder/#understand-how-arg-and-from-interact
ARG PROJECT
ENV GOOGLE_CLOUD_PROJECT ${PROJECT}
ENTRYPOINT ["worker.py"]

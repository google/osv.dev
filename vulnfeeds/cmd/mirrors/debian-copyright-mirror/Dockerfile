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

FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine@sha256:bd145cbd85b9613a855487e77076ff3633cdbbd2f91d6f93e3a77c59e5710ca9

RUN apk add py3-yaml

COPY ./debian-copyright-mirror.sh /
COPY ./debian-copyright-mirror.py /

ENTRYPOINT ["/debian-copyright-mirror.sh"]

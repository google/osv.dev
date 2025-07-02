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

FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine@sha256:f0f43981a0b69a5d6390a1e9cc47e2355a873e1c1e9d6d1b923cbded92bda671

RUN apk add py3-yaml

COPY ./debian-copyright-mirror.sh /
COPY ./debian-copyright-mirror.py /

ENTRYPOINT ["/debian-copyright-mirror.sh"]

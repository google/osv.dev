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

FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine@sha256:5b9ce432f4f2230e7bfd02f51d6c97ec952456a6910c33c1542dc7cffbb80dcf

RUN apk add py3-yaml

COPY ./debian-copyright-mirror.sh /
COPY ./debian-copyright-mirror.py /

ENTRYPOINT ["/debian-copyright-mirror.sh"]

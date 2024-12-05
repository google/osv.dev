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

FROM gcr.io/oss-vdb/worker

COPY exporter.py /usr/local/bin
COPY export_runner.py /usr/local/bin
RUN chmod 755 /usr/local/bin/exporter.py
RUN chmod 755 /usr/local/bin/export_runner.py
ENTRYPOINT ["export_runner.py"]

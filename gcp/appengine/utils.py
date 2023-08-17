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
"""Utils."""

import os


def is_prod():
  # TODO(michaelkedar): Cloud Run/App Engine have different ways to check this
  # remove the App Engine header check when moving away from App Engine.
  # This function actually checks if it's running on gcp (on prod OR staging)
  # and it's only used for Redis cache (which has its own env vars) and logging.
  # Consider removing this altogether.
  return 'GAE_ENV' in os.environ or 'K_SERVICE' in os.environ

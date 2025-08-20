# Copyright 2025 Google LLC
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
"""Miscellaneous utility functions."""

import os
import google.auth
from google.auth.exceptions import DefaultCredentialsError

_google_cloud_project = None


def get_google_cloud_project() -> str:
  """Determine the current Google Cloud Project.
  
  returns an empty string if project could not be determined.
  """
  global _google_cloud_project
  if _google_cloud_project is not None:
    return _google_cloud_project

  # google.auth.default will also check this env var, but this is cheaper.
  _google_cloud_project = os.getenv('GOOGLE_CLOUD_PROJECT')
  if _google_cloud_project:
    return _google_cloud_project

  try:
    _, _google_cloud_project = google.auth.default()
    if _google_cloud_project:
      return _google_cloud_project
  except DefaultCredentialsError:
    pass

  _google_cloud_project = ''
  return _google_cloud_project

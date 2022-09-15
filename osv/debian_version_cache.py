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
"""Caches the debian package first version dataframe"""
import requests
import json

from . import cache

CLOUD_API_CACHE_URL_TEMPLATE = (
    'https://storage.googleapis.com/debian-osv/first_package_output/'
    '{version}.json')
CACHE_DURATION_SECONDS = 60 * 60 * 24
TIMEOUT = 30  # Timeout for HTTP(S) requests

debian_version_cache = cache.InMemoryCache()


class ReleaseNotFoundError(Exception):
  """Release cannot be found.

  Most likely a new release that haven't been picked up yet.

  Args:
      release_number: the release number that cannot be found.
  """
  release_number: str

  def __init__(self, release_number):
    super().__init__(release_number)
    self.release_number = release_number


@cache.cached(debian_version_cache, 24 * 60 * 60)
def _get_first_versions_for_release(release_number: str):
  """Gets the first version mapping for specific release number"""
  response = requests.get(
      CLOUD_API_CACHE_URL_TEMPLATE.format(version=release_number),
      timeout=TIMEOUT)
  if response.status_code == 404:
    raise ReleaseNotFoundError(release_number)

  return json.loads(response.text)


def get_first_package_version(package_name: str, release_number: str) -> str:
  """Get first package version"""

  try:
    return _get_first_versions_for_release(release_number)[package_name]
  except KeyError:
    # The package is not added when the image is first seen.
    # So it is safe to leave it as 0, indicating the earliest version
    # given by the snapshot API
    return '0'

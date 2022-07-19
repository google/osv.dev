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

from . import cache

CLOUD_API_CACHE_URL_TEMPLATE = 'https://storage.googleapis.com/debian-osv/first_package_output/{version}/{package}'
CACHE_DURATION_SECONDS = 60 * 60 * 24

debian_version_cache = cache.InMemoryCache()


class VersionNotFoundError(Exception):
  """First version of package in release can't be found"""
  pass


@cache.Cached(debian_version_cache, 24 * 60 * 60)
def get_first_package_version(package_name: str, release_number: str) -> str:
  """Get first package version"""

  response = requests.get(
      CLOUD_API_CACHE_URL_TEMPLATE.format(
          version=release_number, package=package_name))
  if response.status_code == 404:
    raise VersionNotFoundError()

  return response.text

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
import gzip
import typing
from urllib import request
import json

from . import cache

CLOUD_API_CACHE_URL = 'https://storage.googleapis.com/debian-osv/first_package_cache.json.gz'
CACHE_DURATION_SECONDS = 60 * 60 * 24

debian_version_cache = cache.InMemoryCache()


def _update_from_cloud_cache():
  """Update the debian version cache from the Google cloud link"""
  res = request.urlopen(CLOUD_API_CACHE_URL)

  item: typing.Dict[str, typing.Dict] = json.loads(gzip.decompress(res.read()))
  for release, sources in item.items():
    if not sources:
      continue

    for package, version in sources.items():
      debian_version_cache.set((package, release), version,
                               CACHE_DURATION_SECONDS)


def get_first_package_version(package_name: str, release_number: str) -> str:
  """Get first package version"""

  result = debian_version_cache.get((package_name, release_number))
  if result:
    return result

  _update_from_cloud_cache()
  # Try again after updating cloud cache
  result = debian_version_cache.get((package_name, release_number))
  if result:
    return result

  # The package is not added when the image is first seen.
  # So it is safe to return 0, indicating the earliest version
  # given by the snapshot API
  return '0'

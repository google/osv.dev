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

CLOUD_API_CACHE_URL = 'https://storage.googleapis.com/debian-osv/first_package_cache.json.gz'
debian_version_cache = None


def _initiate_from_cloud_cache(
    force_reload: bool = False) -> typing.Dict[str, typing.Dict]:
  """Load the debian version cache from the Google cloud link, if it hasn't been loaded yet"""
  global debian_version_cache
  if debian_version_cache is None or force_reload:
    res = request.urlopen(CLOUD_API_CACHE_URL)
    debian_version_cache = json.loads(gzip.decompress(res.read()))


def get_first_package_version(package_name: str, release_number: str) -> str:
  """Get first package version"""
  if debian_version_cache is None:
    _initiate_from_cloud_cache()

  try:
    return debian_version_cache[release_number][package_name]
  except KeyError:
    # The package is not added when the image is first seen.
    # So it is safe to return 0, indicating the earliest version
    # given by the snapshot API
    return '0'

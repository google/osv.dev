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
"""Debian ecosystem helper."""

import json
import logging
import requests

from ..third_party.univers.debian import Version as DebianVersion

from . import config
from .helper_base import Ecosystem, EnumerateError
from .. import cache
from ..request_helper import RequestError, RequestHelper

# TODO(another-rex): Update this to use dynamically
# change depending on the project
CLOUD_API_CACHE_URL_TEMPLATE = (
    'https://storage.googleapis.com/debian-osv/first_package_output/'
    '{version}.json')
CACHE_DURATION_SECONDS = 60 * 60 * 24

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
      timeout=config.timeout)
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


class Debian(Ecosystem):
  """Debian ecosystem"""

  _API_PACKAGE_URL = 'https://snapshot.debian.org/mr/package/{package}/'
  debian_release_ver: str

  def __init__(self, debian_release_ver: str):
    self.debian_release_ver = debian_release_ver

  def sort_key(self, version):
    if not DebianVersion.is_valid(version):
      # If debian version is not valid, it is most likely an invalid fixed
      # version then sort it to the last/largest element
      return DebianVersion(999999, '999999')
    return DebianVersion.from_string(version)

  def enumerate_versions(self,
                         package,
                         introduced,
                         fixed=None,
                         last_affected=None,
                         limits=None):
    url = self._API_PACKAGE_URL.format(package=package.lower())
    request_helper = RequestHelper(config.shared_cache)
    try:
      text_response = request_helper.get(url)
    except RequestError as ex:
      if ex.response.status_code == 404:
        raise EnumerateError(f'Package {package} not found') from ex
      raise RuntimeError('Failed to get Debian versions for '
                         f'{package} with: {ex.response.text}') from ex

    response = json.loads(text_response)
    raw_versions: list[str] = [x['version'] for x in response['result']]

    # Remove rare cases of unknown versions
    def version_is_valid(v):
      if not DebianVersion.is_valid(v):
        logging.warning('Package %s has invalid version: %s', package, v)
        return False

      return True

    versions = [v for v in raw_versions if version_is_valid(v)]
    # Sort to ensure it is in the correct order
    self.sort_versions(versions)
    # The only versions with +deb
    versions = [
        x for x in versions
        if '+deb' not in x or f'+deb{self.debian_release_ver}' in x
    ]

    if introduced == '0':
      # Update introduced to the first version of the debian version
      introduced = get_first_package_version(package, self.debian_release_ver)

    if fixed is not None and not DebianVersion.is_valid(fixed):
      logging.warning(
          'Package %s has invalid fixed version: %s. In debian release %s',
          package, fixed, self.debian_release_ver)
      return []

    return self._get_affected_versions(versions, introduced, fixed,
                                       last_affected, limits)

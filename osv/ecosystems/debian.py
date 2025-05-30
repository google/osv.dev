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
from typing import Any, Dict, List, Optional

import requests

from ..third_party.univers.debian import Version as DebianVersion

from . import config
from .helper_base import Ecosystem, EnumerateError
from .. import cache
from ..request_helper import RequestError, RequestHelper

# TODO(rexpan): Move this to a common place for all ecosystems.
# Or make it configurable.
_REQUEST_TIMEOUT: int = 30  # Timeout for HTTP(S) requests

# TODO(another-rex): Update this to use dynamically
# change depending on the project
CLOUD_API_CACHE_URL_TEMPLATE = (
    'https://storage.googleapis.com/debian-osv/first_package_output/'
    '{version}.json')
CACHE_DURATION_SECONDS: int = 60 * 60 * 24

debian_version_cache: cache.Cache = cache.InMemoryCache()


class ReleaseNotFoundError(Exception):
  """Release cannot be found.

  Most likely a new release that haven't been picked up yet.

  Args:
      release_number: the release number that cannot be found.
  """
  release_number: str

  def __init__(self, release_number: str) -> None:
    super().__init__(release_number)
    self.release_number = release_number


@cache.cached(debian_version_cache, CACHE_DURATION_SECONDS)
def _get_first_versions_for_release(release_number: str) -> Dict[str, str]:
  """Gets the first version mapping for specific release number"""
  response = requests.get(
      CLOUD_API_CACHE_URL_TEMPLATE.format(version=release_number),
      timeout=_REQUEST_TIMEOUT)
  if response.status_code == 404:
    raise ReleaseNotFoundError(release_number)

  return json.loads(response.text)


def get_first_package_version(package_name: str, release_number: str) -> str:
  """Get first package version"""

  try:
    # Type Any because the structure of the JSON is not strictly defined.
    # It's a dictionary mapping package names (strings) to version strings.
    data: Any = _get_first_versions_for_release(release_number)
    return data[package_name]
  except KeyError:
    # The package is not added when the image is first seen.
    # So it is safe to leave it as 0, indicating the earliest version
    # given by the snapshot API
    return '0'


class Debian(Ecosystem):
  """Debian ecosystem"""

  _API_PACKAGE_URL: str = 'https://snapshot.debian.org/mr/package/{package}/'
  debian_release_ver: str

  def __init__(self, debian_release_ver: str) -> None:
    self.debian_release_ver = debian_release_ver

  def sort_key(self, version: str) -> DebianVersion:
    if not DebianVersion.is_valid(version):
      # If debian version is not valid, it is most likely an invalid fixed
      # version then sort it to the last/largest element
      return DebianVersion(999999, '999999')  # pytype: disable=wrong-arg-types
    return DebianVersion.from_string(version)

  def enumerate_versions(self,
                         package: str,
                         introduced: str,
                         fixed: Optional[str] = None,
                         last_affected: Optional[str] = None,
                         limits: Optional[List[str]] = None) -> List[str]:
    url: str = self._API_PACKAGE_URL.format(package=package.lower())
    request_helper: RequestHelper = RequestHelper(
        config.shared_cache)  # pytype: disable=module-attr
    try:
      text_response: str = request_helper.get(url)
    except RequestError as ex:
      if ex.response is not None and ex.response.status_code == 404:
        raise EnumerateError(f'Package {package} not found') from ex
      # Ensure ex.response is not None before accessing .text
      response_text = ex.response.text if ex.response is not None else "Unknown error"
      raise RuntimeError('Failed to get Debian versions for '
                         f'{package} with: {response_text}') from ex

    response_json: Any = json.loads(text_response)
    # Assuming 'result' is a list of dicts, each with a 'version' key
    raw_versions: List[str] = [
        x['version'] for x in response_json.get('result', [])
    ]

    # Remove rare cases of unknown versions
    def version_is_valid(v_str: str) -> bool:
      if not DebianVersion.is_valid(v_str):
        logging.warning('Package %s has invalid version: %s', package, v_str)
        return False
      return True

    versions: List[str] = [v for v in raw_versions if version_is_valid(v)]
    # Sort to ensure it is in the correct order
    self.sort_versions(versions)
    # The only versions with +deb
    versions = [
        x for x in versions
        if '+deb' not in x or f'+deb{self.debian_release_ver}' in x
    ]

    processed_introduced: str = introduced
    if introduced == '0':
      # Update introduced to the first version of the debian version
      processed_introduced = get_first_package_version(
          package, self.debian_release_ver)

    if fixed is not None and not DebianVersion.is_valid(fixed):
      logging.warning(
          'Package %s has invalid fixed version: %s. In debian release %s',
          package, fixed, self.debian_release_ver)
      return []

    return self._get_affected_versions(versions, processed_introduced, fixed,
                                       last_affected, limits)

  @property
  def supports_comparing(self) -> bool:
    return True

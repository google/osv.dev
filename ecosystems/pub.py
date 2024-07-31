# Copyright 2023 Google LLC
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
"""Pub ecosystem helper."""

import functools
import json

from . import config
from .helper_base import Ecosystem, EnumerateError
from .. import semver_index
from ..request_helper import RequestError, RequestHelper

# Pub follows SemVer 2.0.0-rc.1:
# https://semver.org/spec/v2.0.0-rc.1.html
# Differences from SemVer 2.0.0 are described at
# https://pub.dev/packages/pub_semver
# Only difference that affects us is the inclusion of build suffix when
# ordering.
#  - Build suffixes are parsed the same as pre-release suffixes.
#  - Pre-release suffixes are evaluated before build suffixes.
#  - Versions with build suffixes come after versions without.
#    e.g. 1.0.0-pre < 1.0.0-pre+build < 1.0.0 < 1.0.0+build
# SemVer 2.0.0-rc.1 also does not explcitly disallow empty identifiers or
# leading 0s on numeric identifiers, but our SemVer implementation also will
# parse these cases.


@functools.total_ordering
class Version:
  """Pub version."""

  def __init__(self, semver):
    # Tuple comparison of (semver,) or (semver, build) is consistent with
    # desired ordering.
    if semver.build:
      # Reuse normalize_prerelease to so that the
      # build suffix can be compared lexicographically.
      self._version = (semver, semver_index.normalize_prerelease(semver.build))
    else:
      self._version = (semver,)

  def __lt__(self, other):
    return self._version < other._version

  def __eq__(self, other):
    return self._version == other._version

  @classmethod
  def from_string(cls, str_version):
    return Version(semver_index.parse(str_version))


class Pub(Ecosystem):
  """Pub ecosystem"""

  _API_PACKAGE_URL = 'https://pub.dev/api/packages/{package}'

  def sort_key(self, version):
    """Sort key."""
    return Version.from_string(version)

  def enumerate_versions(self,
                         package,
                         introduced,
                         fixed=None,
                         last_affected=None,
                         limits=None):
    """Enumerate versions."""
    url = self._API_PACKAGE_URL.format(package=package.lower())
    request_helper = RequestHelper(config.shared_cache)
    try:
      text_response = request_helper.get(url)
    except RequestError as ex:
      if ex.response.status_code == 404:
        raise EnumerateError(f'Package {package} not found') from ex
      raise RuntimeError('Failed to get Pub versions for '
                         f'{package} with: {ex.response.text}') from ex

    response = json.loads(text_response)
    versions: list[str] = [x['version'] for x in response['versions']]
    self.sort_versions(versions)

    return self._get_affected_versions(versions, introduced, fixed,
                                       last_affected, limits)

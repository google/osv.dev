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
"""RubyGems ecosystem helper."""

import requests

from ..third_party.univers.gem import GemVersion, InvalidVersionError

from . import config
from .helper_base import Ecosystem, EnumerateError


class RubyGems(Ecosystem):
  """RubyGems ecosystem."""

  _API_PACKAGE_URL = 'https://rubygems.org/api/v1/versions/{package}.json'

  def sort_key(self, version):
    """Sort key."""
    # If version is not valid, it is most likely an invalid input
    # version then sort it to the last/largest element
    try:
      return GemVersion(version)
    except InvalidVersionError:
      return GemVersion('999999')

  def enumerate_versions(self,
                         package,
                         introduced,
                         fixed=None,
                         last_affected=None,
                         limits=None):
    """Enumerate versions."""
    response = requests.get(
        self._API_PACKAGE_URL.format(package=package), timeout=config.timeout)
    if response.status_code == 404:
      raise EnumerateError(f'Package {package} not found')
    if response.status_code != 200:
      raise RuntimeError(
          f'Failed to get RubyGems versions for {package} with: {response.text}'
      )

    response = response.json()
    versions = [entry['number'] for entry in response]

    self.sort_versions(versions)
    return self._get_affected_versions(versions, introduced, fixed,
                                       last_affected, limits)

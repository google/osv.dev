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
"""PyPI ecosystem helper."""

import packaging.version
import requests

from . import config
from .helper_base import Ecosystem, EnumerateError


class PyPI(Ecosystem):
  """PyPI ecosystem helpers."""

  _API_PACKAGE_URL = 'https://pypi.org/pypi/{package}/json'

  def sort_key(self, version):
    """Sort key."""
    # version.parse() handles invalid versions by returning LegacyVersion()
    return packaging.version.parse(version)

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
          f'Failed to get PyPI versions for {package} with: {response.text}')

    response = response.json()
    versions = list(response['releases'].keys())
    self.sort_versions(versions)

    return self._get_affected_versions(versions, introduced, fixed,
                                       last_affected, limits)

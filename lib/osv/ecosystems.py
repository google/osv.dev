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
"""Ecosystem helpers."""

import bisect
import packaging.version

import requests

from . import semver_index


class Ecosystem:
  """Ecosystem helpers."""

  def _before_limits(self, version, limits):
    """Return whether or not the given version is before any limits."""
    if not limits or '*' in limits:
      return True

    return any(
        self.sort_key(version) < self.sort_key(limit) for limit in limits)

  def sort_key(self, version):
    """Sort key."""
    raise NotImplementedError

  def sort_versions(self, versions):
    """Sort versions."""
    versions.sort(key=self.sort_key)

  def enumerate_versions(self, package, introduced, fixed, limits=None):
    """Enumerate versions."""
    raise NotImplementedError

  @property
  def is_semver(self):
    return False


class SemverEcosystem(Ecosystem):
  """Generic semver ecosystem helpers."""

  def sort_key(self, version):
    """Sort key."""
    return semver_index.parse(version)

  def enumerate_versions(self, package, introduced, fixed, limits=None):
    """Enumerate versions (no-op)."""
    del package
    del introduced
    del fixed
    del limits

  @property
  def is_semver(self):
    return True


Crates = SemverEcosystem
Go = SemverEcosystem


class PyPI(Ecosystem):
  """PyPI ecosystem helpers."""

  _API_PACKAGE_URL = 'https://pypi.org/pypi/{package}/json'

  def sort_key(self, version):
    """Sort key."""
    return packaging.version.parse(version)

  def enumerate_versions(self, package, introduced, fixed, limits=None):
    """Enumerate versions."""
    response = requests.get(self._API_PACKAGE_URL.format(package=package))
    response = response.json()
    versions = list(response['releases'].keys())
    self.sort_versions(versions)

    parsed_versions = [packaging.version.parse(v) for v in versions]

    if introduced:
      introduced = packaging.version.parse(introduced)
      start_idx = bisect.bisect_left(parsed_versions, introduced)
    else:
      start_idx = 0

    if fixed:
      fixed = packaging.version.parse(fixed)
      end_idx = bisect.bisect_left(parsed_versions, fixed)
    else:
      end_idx = len(versions)

    affected = versions[start_idx:end_idx]
    return [v for v in affected if self._before_limits(v, limits)]


_ecosystems = {
    'crates.io': Crates(),
    'Go': Go(),
    'PyPI': PyPI(),
}


def get(name):
  """Get ecosystem helpers for a given ecosytem."""
  return _ecosystems.get(name)

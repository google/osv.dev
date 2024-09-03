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
"""Ecosystem helpers base classes."""

from abc import ABC, abstractmethod
import bisect
from typing import Any
import requests
from urllib.parse import quote

from . import config


class EnumerateError(Exception):
  """Non-retryable version enumeration error."""


class Ecosystem(ABC):
  """Ecosystem helpers."""

  @property
  def name(self):
    """Get the name of the ecosystem."""
    return self.__class__.__name__

  def _before_limits(self, version, limits):
    """Return whether the given version is before any limits."""
    if not limits or '*' in limits:
      return True

    return any(
        self.sort_key(version) < self.sort_key(limit) for limit in limits)

  def next_version(self, package, version):
    """Get the next version after the given version."""
    versions = self.enumerate_versions(package, version, fixed=None)
    # Check if the key used for sorting is equal as sometimes different
    # strings could evaluate to the same version.
    if versions and self.sort_key(versions[0]) != self.sort_key(version):
      # Version does not exist, so use the first one that would sort
      # after it (which is what enumerate_versions returns).
      return versions[0]

    if len(versions) > 1:
      return versions[1]

    return None

  @abstractmethod
  def sort_key(self, version: str) -> Any:
    """Sort key."""

  def sort_versions(self, versions):
    """Sort versions."""
    versions.sort(key=self.sort_key)

  @abstractmethod
  def enumerate_versions(self,
                         package,
                         introduced,
                         fixed=None,
                         last_affected=None,
                         limits=None):
    """Enumerate versions."""

  def _get_affected_versions(self, versions, introduced, fixed, last_affected,
                             limits):
    """Get affected versions.

    Args:
      versions: a list of version strings.
      introduced: a version string.
      fixed: a version string.
      last_affected: a version string.
      limits: a version string.

    Returns:
      A list of affected version strings.
    """
    parsed_versions = [self.sort_key(v) for v in versions]

    if introduced == '0':
      introduced = None

    if introduced:
      introduced = self.sort_key(introduced)
      start_idx = bisect.bisect_left(parsed_versions, introduced)
    else:
      start_idx = 0

    if fixed:
      fixed = self.sort_key(fixed)
      end_idx = bisect.bisect_left(parsed_versions, fixed)
    elif last_affected:
      last_affected = self.sort_key(last_affected)
      end_idx = bisect.bisect_right(parsed_versions, last_affected)
    else:
      end_idx = len(versions)

    affected = versions[start_idx:end_idx]
    return [v for v in affected if self._before_limits(v, limits)]

  @property
  def is_semver(self):
    return False

  @property
  def supports_ordering(self):
    return True

  @property
  def supports_comparing(self):
    """Determines whether to use affected version range comparison
    for API queries."""
    return False


class OrderingUnsupportedEcosystem(Ecosystem):
  """Placeholder ecosystem helper for unimplemented ecosystems."""

  def sort_key(self, version):
    raise NotImplementedError('Ecosystem helper does not support sorting')

  def enumerate_versions(self,
                         package,
                         introduced,
                         fixed=None,
                         last_affected=None,
                         limits=None):
    raise NotImplementedError('Ecosystem helper does not support enumeration')

  @property
  def supports_ordering(self):
    return False


class DepsDevMixin(Ecosystem, ABC):
  """deps.dev mixin."""

  _DEPS_DEV_PACKAGE_URL = \
      'https://api.deps.dev/v3alpha/systems/{system}/packages/{package}'

  _DEPS_DEV_ECOSYSTEM_MAP = {
      'Maven': 'maven',
      'PyPI': 'pypi',
  }

  def _deps_dev_enumerate(self,
                          package,
                          introduced,
                          fixed=None,
                          last_affected=None,
                          limits=None):
    """Use deps.dev to get list of versions."""
    ecosystem = self._DEPS_DEV_ECOSYSTEM_MAP[self.name]
    url = self._DEPS_DEV_PACKAGE_URL.format(
        system=ecosystem, package=quote(package, safe=''))
    response = requests.get(url, timeout=config.timeout)
    if response.status_code == 404:
      raise EnumerateError(f'Package {package} not found')
    if response.status_code != 200:
      raise RuntimeError(
          f'Failed to get {ecosystem} versions for {package} with: '
          f'{response.status_code}')
    response = response.json()
    versions = [v['versionKey']['version'] for v in response['versions']]
    self.sort_versions(versions)
    return self._get_affected_versions(versions, introduced, fixed,
                                       last_affected, limits)

# Copyright 2025 Google LLC
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
"""Ecosystems base classes."""
from abc import ABC, abstractmethod
from typing import Any, Iterable
from warnings import deprecated
import bisect
import functools
import re
import requests
from urllib.parse import quote

from . import config


@functools.total_ordering
class VersionKey:
  """A wrapper class for version keys."""

  _key: Any
  _is_zero: bool
  _is_invalid: bool
  _error: Exception | None

  def __init__(self,
               key: Any = None,
               is_zero: bool = False,
               is_invalid: bool = False,
               error: Exception | None = None):
    self._key = key
    self._is_zero = is_zero
    self._is_invalid = is_invalid
    self._error = error

  @property
  def is_invalid(self):
    return self._is_invalid

  def __lt__(self, other):
    if not isinstance(other, VersionKey):
      return NotImplemented

    # Invalid versions are greater than everything else
    if self._is_invalid:
      # If both are invalid, they are equal (not less than)
      return False
    if other._is_invalid:
      return True

    if self._is_zero:
      return not other._is_zero

    if other._is_zero:
      return False

    return self._key < other._key

  def __eq__(self, other):
    if not isinstance(other, VersionKey):
      return NotImplemented

    if self._is_invalid:
      return other._is_invalid

    if other._is_invalid:
      return False

    if self._is_zero:
      return other._is_zero

    if other._is_zero:
      return False

    return self._key == other._key

  def __repr__(self):
    if self._is_invalid:
      return 'VersionKey(is_invalid=True)'
    if self._is_zero:
      return 'VersionKey(is_zero=True)'
    return f'VersionKey({self._key})'


_VERSION_ZERO = VersionKey(is_zero=True)
_VERSION_INVALID = VersionKey(is_invalid=True)


class OrderedEcosystem(ABC):
  """Ecosystem helper that supports comparison between versions."""

  def __init__(self, suffix: str | None = None):
    """init method for all ecosystem helpers.
    
    `suffix` is optionally used on ecosystems that use them.
    e.g. Alpine:v3.16 would use suffix='v3.16'
    """
    self.suffix = suffix

  @abstractmethod
  def _sort_key(self, version: str) -> Any:
    """Comparable key for a version.
    
    If the version string is invalid, raise a ValueError.
    """

  def sort_key(self, version: str) -> VersionKey:
    """Sort key."""
    if version == '0':
      return _VERSION_ZERO

    try:
      return VersionKey(self._sort_key(version))
    except ValueError as e:
      # Store the exception for potential logging/debugging.
      return VersionKey(is_invalid=True, error=e)

  def sort_versions(self, versions: list[str]):
    """Sort versions."""
    versions.sort(key=self.sort_key)

  def coarse_version(self, version: str) -> str:
    """Convert a version string for this ecosystem to a lexicographically
    sortable string in the form:

    EE:XXXXXXXX.YYYYYYYY.ZZZZZZZZ
    where:
    EE is the 0-padded 2-digit epoch number (or equivalent),
    XXXXXXXX is the 0-padded 8-digit major version (or equivalent),
    YYYYYYYY is the 0-padded 8-digit minor version (or equivalent),
    ZZZZZZZZ is the 0-padded 8-digit patch version (or equivalent).

    The returned string is used for database range queries
    (e.g. coarse_min <= v <= coarse_max).
    It does not need to be a perfect representation of the version, but it
    MUST be monotonically non-decreasing with respect to the ecosystem's sort
    order.
    i.e. if v1 < v2, then coarse_version(v1) <= coarse_version(v2).

    Version string '0' should map to 00:0000000.00000000.00000000

    Should raise a ValueError if the version string is invalid.
    """
    raise NotImplementedError(
        f'coarse_version not implemented for {self.__class__.__name__}')


class EnumerateError(Exception):
  """Non-retryable version enumeration error."""


class EnumerableEcosystem(OrderedEcosystem, ABC):
  """Ecosystem helper that supports version enumeration."""

  @abstractmethod
  def enumerate_versions(self,
                         package: str,
                         introduced: str | None,
                         fixed: str | None = None,
                         last_affected: str | None = None,
                         limits: list[str] | None = None) -> list[str]:
    """Enumerate known versions of a package in a given version range."""

  def _before_limits(self, version: str, limits: list[str] | None) -> bool:
    """Return whether the given version is before any limits."""
    if not limits or '*' in limits:
      return True

    return any(
        self.sort_key(version) < self.sort_key(limit) for limit in limits)

  def _get_affected_versions(self, versions: list[str], introduced: str | None,
                             fixed: str | None, last_affected: str | None,
                             limits: list[str] | None) -> list[str]:
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

  @deprecated('Avoid using this method. '
              'It is provided only to maintain existing tooling.')
  def next_version(self, package: str, version: str) -> str | None:
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


class DepsDevMixin(EnumerableEcosystem, ABC):
  """deps.dev mixin."""

  _DEPS_DEV_PACKAGE_URL = \
      'https://api.deps.dev/v3alpha/systems/{system}/packages/{package}'

  @property
  @abstractmethod
  def deps_dev_system(self) -> str:
    """The deps.dev system name."""

  def _deps_dev_enumerate(self,
                          package,
                          introduced,
                          fixed=None,
                          last_affected=None,
                          limits=None):
    """Use deps.dev to get list of versions."""
    url = self._DEPS_DEV_PACKAGE_URL.format(
        system=self.deps_dev_system, package=quote(package, safe=''))
    response = requests.get(url, timeout=config.timeout)
    if response.status_code == 404:
      raise EnumerateError(f'Package {package} not found')
    if response.status_code != 200:
      raise RuntimeError(
          f'Failed to get {self.deps_dev_system} versions for {package} with: '
          f'{response.status_code}')
    response = response.json()
    versions = [v['versionKey']['version'] for v in response['versions']]
    self.sort_versions(versions)
    return self._get_affected_versions(versions, introduced, fixed,
                                       last_affected, limits)


def coarse_version_generic(version: str,
                           separators_regex=r'[.]',
                           trim_regex=r'[-+]',
                           implicit_split=False,
                           empty_as: str | None = None) -> str:
  """
  Convert a version string into a coarse, lexicographically comparable string.
  
  Format: 00:00000000.00000000.00000000
  (Epoch:Major.Minor.Patch)
  
  The Epoch is always 00.
  Only the first 3 integer components (Major, Minor, Patch) are used.
  
  Args:
    version: The version string to convert.
    separators_regex: Regex for separators (default: r'[.]').
    trim_regex: Regex for characters to trim after (default: r'[-+]'). 
                If None, no trimming is performed.
    implicit_split: If True, splits on transitions between digits and non-digits
                    (in addition to separators_regex).
    empty_as: If not None, treats empty parts as the given string instead of
              removing them.

  Returns:
    A string in the format 00:00000000.00000000.00000000
  """
  if version == '0':
    return '00:00000000.00000000.00000000'

  main = version
  if trim_regex:
    # Trim off trailing components (e.g. prerelease/build)
    main = re.split(trim_regex, version, maxsplit=1)[0]
  parts = re.split(separators_regex, main)
  if implicit_split:
    # Also split on transitions between digits and non-digits
    parts = [p for part in parts for p in re.findall(r'^$|\d+|\D+', part)]

  # Filter empty parts or treat as zero
  if empty_as is not None:
    parts = [p if p else empty_as for p in parts]
  else:
    parts = [p for p in parts if p]

  # Extract up to 3 integer components
  components = []
  overflow = False
  for p in parts[:3]:
    if not p.isdecimal():
      break
    val = int(p)
    if val > 99999999:
      val = 99999999
      overflow = True
    components.append(val)
    if overflow:
      break

  # Pad with zeros to ensure 3 components
  # If we overflowed, we should pad with MAX instead of 0
  pad_value = 99999999 if overflow else 0
  while len(components) < 3:
    components.append(pad_value)

  return f'00:{components[0]:08d}.{components[1]:08d}.{components[2]:08d}'


def coarse_version_from_ints(parts: Iterable[int]) -> str:
  """
  Convert a list of integers into a coarse version string.
  
  Format: 00:00000000.00000000.00000000
  (Epoch:Major.Minor.Patch)
  
  The Epoch is always 00.
  Only the first 3 integer components (Major, Minor, Patch) are used.
  
  Args:
    parts: The list of integers to convert.
  """
  components = []
  overflow = False
  for p in parts:
    if p < 0:
      # A negative part doesn't really make sense
      # but let's just treat it and all following parts as 0
      components.append(0)
      break
    if p > 99999999:
      p = 99999999
      overflow = True
    components.append(p)
    if overflow or len(components) == 3:
      break

  # Pad with zeros to ensure 3 components
  # If we overflowed, we should pad with MAX instead of 0
  pad_value = 99999999 if overflow else 0
  while len(components) < 3:
    components.append(pad_value)

  return f'00:{components[0]:08d}.{components[1]:08d}.{components[2]:08d}'

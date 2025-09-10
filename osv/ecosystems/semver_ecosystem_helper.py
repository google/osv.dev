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
"""Ecosystem helper for ecosystems using SemVer."""
from warnings import deprecated

from .ecosystems_base import OrderedEcosystem
from .. import semver_index


class SemverLike(OrderedEcosystem):
  """Ecosystem helper for ecosystems that use SEMVER-compatible versioning,
  but use the ECOSYSTEM version type."""

  def sort_key(self, version):
    """Sort key."""
    try:
      return semver_index.parse(version)
    except ValueError:
      # If a user gives us an unparsable semver version,
      # treat it as a very large version so as to not match anything.
      return semver_index.parse('999999')


class SemverEcosystem(SemverLike):
  """Ecosystems which use the 'SEMVER' OSV version type"""

  @deprecated('Avoid using this method. '
              'It is provided only to maintain existing tooling.')
  def next_version(self, package, version):
    """Get the next version after the given version."""
    del package  # Unused.
    parsed_version = semver_index.parse(version)
    if parsed_version.prerelease:
      return version + '.0'

    return str(parsed_version.bump_patch()) + '-0'

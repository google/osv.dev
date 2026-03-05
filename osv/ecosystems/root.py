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
"""Root ecosystem helper."""

import re
import packaging_legacy.version
from .ecosystems_base import OrderedEcosystem
from .maven import Version as MavenVersion
from ..third_party.univers.alpine import AlpineLinuxVersion
from ..third_party.univers.debian import Version as DebianVersion


class Root(OrderedEcosystem):
  """Root container security ecosystem.

  Root provides patched container images across multiple base distributions
  and application ecosystems. The ecosystem uses hierarchical variants:
  - Root:Alpine:3.18 - Alpine Linux 3.18 based images
  - Root:Debian:12 - Debian 12 based images
  - Root:Ubuntu:22.04 - Ubuntu 22.04 based images
  - Root:PyPI - Python packages
  - Root:npm - npm packages

  Version formats:
  - Alpine: <version>-r<patch_number> (e.g., 1.0.0-r10071)
  - Python: <version>+root.io.<patch_number> (e.g., 1.0.0+root.io.1)
  - Others: <version>.root.io.<patch_number> (e.g., 1.0.0.root.io.1)
  """

  def _sort_key(self, version: str):
    """Generate sort key for Root version strings.

    Delegates to the appropriate ecosystem version parser based on the
    ecosystem suffix (e.g., :Alpine:3.18, :Debian:12, :npm).

    Args:
      version: Version string to parse

    Returns:
      Tuple with (version_object, root_patch) for sorting
    """
    upstream_version = version
    root_patch = 0

    # Extract Root-specific suffixes
    # Python format: <version>+root.io.<number>
    python_match = re.match(r'^(.+?)\+root\.io\.(\d+)$', version)
    if python_match:
      upstream_version = python_match.group(1)
      root_patch = int(python_match.group(2))

    # Generic format: <version>.root.io.<number>
    other_match = re.match(r'^(.+?)\.root\.io\.(\d+)$', version)
    if other_match:
      upstream_version = other_match.group(1)
      root_patch = int(other_match.group(2))

    # Alpine format with Root suffix: <version>-r<number>
    # Note: Alpine naturally uses -r<revision>
    alpine_match = re.match(r'^(.+?)-r(\d+)$', upstream_version)
    if alpine_match:
      root_patch = int(alpine_match.group(2))

    # Determine the sub-ecosystem from the suffix
    sub_ecosystem = self._get_sub_ecosystem()

    # Parse the upstream version using the appropriate version class
    return self._parse_upstream_version(upstream_version,
                                        sub_ecosystem) + (root_patch,)

  def _get_sub_ecosystem(self) -> str:
    """Extract the sub-ecosystem from the suffix.

    Returns:
      Sub-ecosystem name (e.g., 'Alpine', 'Debian', 'npm', 'PyPI')
    """
    if not self.suffix:
      return 'unknown'

    # Parse suffix like ":Alpine:3.18" -> "Alpine"
    # or ":npm" -> "npm"
    parts = self.suffix.strip(':').split(':')
    if parts:
      return parts[0]
    return 'unknown'

  def _parse_upstream_version(self, version: str, sub_ecosystem: str):
    """Parse upstream version using ecosystem-specific parser.

    Args:
      version: Upstream version string
      sub_ecosystem: Sub-ecosystem name (e.g., 'Alpine', 'Debian', 'npm')

    Returns:
      Tuple with version object for comparison

    Raises:
      ValueError: If the version cannot be parsed by the appropriate parser
    """
    match sub_ecosystem.lower():
      case 'alpine':
        if not AlpineLinuxVersion.is_valid(version):
          raise ValueError(f'Invalid Alpine version: {version}')
        return (AlpineLinuxVersion(version),)

      case 'debian' | 'ubuntu':
        if not DebianVersion.is_valid(version):
          raise ValueError(f'Invalid Debian/Ubuntu version: {version}')
        return (DebianVersion.from_string(version),)

      case 'pypi' | 'python':
        # packaging_legacy.version.parse handles invalid versions gracefully
        # by returning LegacyVersion, so we don't need explicit validation
        return (packaging_legacy.version.parse(version),)

      case 'maven':
        return (MavenVersion.from_string(version),)

      case _:
        return (packaging_legacy.version.parse(version),)

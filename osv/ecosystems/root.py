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
from .ecosystems_base import OrderedEcosystem


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

    Handles multiple version formats:
    - Alpine: 1.0.0-r10071
    - Python: 1.0.0+root.io.1
    - Others: 1.0.0.root.io.1

    Args:
      version: Version string to parse

    Returns:
      Tuple suitable for sorting
    """
    # Try Alpine format: <version>-r<number>
    alpine_match = re.match(r'^(.+?)-r(\d+)$', version)
    if alpine_match:
      upstream = alpine_match.group(1)
      root_patch = int(alpine_match.group(2))
      return self._parse_upstream_version(upstream) + (root_patch,)

    # Try Python format: <version>+root.io.<number>
    python_match = re.match(r'^(.+?)\+root\.io\.(\d+)$', version)
    if python_match:
      upstream = python_match.group(1)
      root_patch = int(python_match.group(2))
      return self._parse_upstream_version(upstream) + (root_patch,)

    # Try other format: <version>.root.io.<number>
    other_match = re.match(r'^(.+?)\.root\.io\.(\d+)$', version)
    if other_match:
      upstream = other_match.group(1)
      root_patch = int(other_match.group(2))
      return self._parse_upstream_version(upstream) + (root_patch,)

    # Fallback: treat as generic version
    return self._parse_upstream_version(version)

  def _parse_upstream_version(self, version: str):
    """Parse upstream version component.

    Attempts to extract numeric and string components for sorting.

    Args:
      version: Upstream version string

    Returns:
      Tuple of parsed components
    """
    parts = []

    # Split on common delimiters
    components = re.split(r'[.-]', version)

    for component in components:
      # Try to parse as integer
      try:
        parts.append(int(component))
      except ValueError:
        # If not numeric, use string comparison
        # Convert to tuple of character codes for consistent sorting
        parts.append(component)

    return tuple(parts)

  def sort_key(self, version: str):
    """Public sort key method.

    Args:
      version: Version string

    Returns:
      Tuple for sorting
    """
    try:
      return self._sort_key(version)
    except Exception:
      # Fallback to string comparison if parsing fails
      return (version,)

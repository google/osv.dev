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
"""Echo ecosystem helper."""

import re

from .debian import DPKG
from .ecosystems_base import OrderedEcosystem
from .maven import Maven
from .pypi import PyPI
from .semver_ecosystem_helper import SemverLike

# Echo secured builds carry a `+echo.N` local/build suffix (e.g. 1.2.3+echo.1).
_ECHO_BUILD_RE = re.compile(r'\+echo\.(\d+)')


def _echo_build_number(version: str) -> int:
  """The `+echo.N` build number for a version (0 if there is none)."""
  match = _ECHO_BUILD_RE.search(version)
  return int(match.group(1)) if match else 0


class Echo(OrderedEcosystem):
  """Echo container security ecosystem.

  Echo provides secured packages across multiple ecosystems:
  - Echo        - Debian-based packages (dpkg versioning)
  - Echo:PyPI   - Python packages (PyPI/PEP 440 versioning)
  - Echo:Maven  - Maven packages (Maven versioning)
  - Echo:npm    - npm packages (SemVer versioning, +echo.N aware)
  """

  def _delegate(self) -> OrderedEcosystem:
    suffix = self.suffix.lower() if self.suffix else ''
    if suffix == 'pypi':
      return PyPI()
    if suffix == 'maven':
      return Maven()
    if suffix == 'npm':
      return SemverLike()
    return DPKG()

  def _sort_key(self, version: str):
    delegate = self._delegate()
    key = delegate._sort_key(version)  # pylint: disable=protected-access
    if isinstance(delegate, SemverLike):
      # SemVer excludes build metadata from precedence, so `1.2.3`,
      # `1.2.3+echo.1` and `1.2.3+echo.2` would all compare equal. PyPI and
      # Maven order `+echo.N` natively (local versions / qualifiers); npm does
      # not, so tie-break on the build number to keep
      # `1.2.3 < 1.2.3+echo.1 < 1.2.3+echo.2 < 1.2.4`.
      return (key, _echo_build_number(version))
    return key

  def coarse_version(self, version: str) -> str:
    return self._delegate().coarse_version(version)

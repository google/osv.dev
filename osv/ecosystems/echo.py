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
from itertools import batched
import packaging_legacy.version

from ..third_party.univers.debian import Version as DebianVersion
from .ecosystems_base import (
    coarse_version_generic,
    coarse_version_from_ints,
    MAX_COARSE_PART,
    OrderedEcosystem,
)


class Echo(OrderedEcosystem):
  """Echo container security ecosystem.

  Echo provides secured packages across multiple ecosystems:
  - Echo        - Debian-based packages (dpkg versioning)
  - Echo:PyPI   - Python packages (PyPI/PEP 440 versioning)
  """

  def _sort_key(self, version: str):
    if self.suffix and self.suffix.lower() == 'pypi':
      return packaging_legacy.version.parse(version)
    if not DebianVersion.is_valid(version):
      raise ValueError(f'Invalid version: {version}')
    return DebianVersion.from_string(version)

  def coarse_version(self, version: str) -> str:
    if self.suffix and self.suffix.lower() == 'pypi':
      return self._pypi_coarse_version(version)
    return self._dpkg_coarse_version(version)

  def _pypi_coarse_version(self, version: str) -> str:
    """Coarse version using PyPI/PEP 440 semantics."""
    ver = packaging_legacy.version.parse(version)
    if isinstance(ver, packaging_legacy.version.LegacyVersion):
      return coarse_version_from_ints([0])

    epoch = ver.epoch
    if version[0].lower() == 'v':
      version = version[1:]
    epochless = version.split('!', 1)[-1]

    return coarse_version_generic(
        epochless,
        separators_regex=r'[.]',
        truncate_regex=r'[+_-]',
        implicit_split=True,
        empty_as=None,
        epoch=epoch)

  def _dpkg_coarse_version(self, version: str) -> str:
    """Coarse version using Debian dpkg semantics."""
    if not DebianVersion.is_valid(version):
      raise ValueError(f'Invalid version: {version}')

    e, p, v = version.partition(':')
    if not p:
      v = e
      e = '0'
    try:
      epoch = int(e)
    except ValueError as exc:
      raise ValueError(f'Invalid version: {version}') from exc

    parts = re.findall(r'^$|\d+|\D+', v)
    int_parts = []
    for couple in batched(parts, 2):
      if not couple[0].isdecimal():
        break
      int_parts.append(int(couple[0]))
      if len(couple) == 1:
        break
      sep = couple[1]
      if sep == '.':
        continue
      if sep[0] == '.':
        int_parts.append(MAX_COARSE_PART + 1)
      break

    return coarse_version_from_ints(int_parts, epoch=epoch)

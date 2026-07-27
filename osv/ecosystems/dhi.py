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
"""Docker Hardened Images ecosystem helper."""

from typing import Any

from .ecosystems_base import OrderedEcosystem


class DHIEcosystem(OrderedEcosystem):
  """Docker Hardened Images advisories use the form
  "Docker Hardened Images:<lineage>:<release>" (e.g.
  "Docker Hardened Images:Alpine:3.23", "Docker Hardened Images:Debian:trixie").

  DHI OS packages are repackaged Alpine (apk) and Debian (dpkg) packages that
  keep their upstream version syntax (e.g. "8.4.0-r0", "7.88.1-10+deb13u2"), so
  version handling must delegate to the lineage ecosystem rather than to semver.

  The caller (``_ecosystems.get``) resolves the inner ecosystem from the
  "<lineage>:<release>" suffix (which is itself a resolvable ecosystem such as
  "Alpine:3.23" or "Debian:trixie") and passes it in. A bare
  "Docker Hardened Images" or an unknown lineage yields no inner; the sort and
  coarse methods then raise ValueError, which OrderedEcosystem.sort_key surfaces
  as an invalid version.
  """

  def __init__(self, suffix: str | None, inner: OrderedEcosystem | None = None):
    super().__init__(suffix)
    self.inner = inner

  def _sort_key(self, version: str) -> Any:
    if self.inner is None:
      raise ValueError('Docker Hardened Images has no lineage ecosystem')
    return self.inner._sort_key(version)  # pylint: disable=protected-access

  def coarse_version(self, version: str) -> str:
    if self.inner is None:
      raise ValueError('Docker Hardened Images has no lineage ecosystem')
    return self.inner.coarse_version(version)

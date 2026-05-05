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
"""TuxCare ecosystem helper."""

from typing import Any

from .ecosystems_base import OrderedEcosystem

_TUXCARE = 'TuxCare'


class TuxCareEcosystem(OrderedEcosystem):
  """TuxCare advisories use the form "TuxCare:<ecosystem>" (e.g.
  "TuxCare:Red Hat", "TuxCare:Alpine:v3.16", "TuxCare:npm") and delegate
  version handling to the inner ecosystem.

  A bare "TuxCare" or a nested "TuxCare:TuxCare:..." is malformed and
  produces an instance with `_inner = None`; calling sort/coarse methods
  on such an instance raises ValueError.
  """

  def __init__(self, suffix: str | None):
    super().__init__(suffix)
    if not _is_valid_inner(suffix):
      self._inner = None
      return
    # Lazy import to avoid circular dependency with _ecosystems.
    from ._ecosystems import get
    self._inner = get(suffix)

  @classmethod
  def is_known_inner(cls, suffix: str | None) -> bool:
    """Whether a TuxCare suffix names a known inner ecosystem."""
    if not _is_valid_inner(suffix):
      return False
    from ._ecosystems import is_known
    return is_known(suffix)

  def _sort_key(self, version: str) -> Any:
    if self._inner is None:
      raise ValueError('TuxCare ecosystem has no resolvable inner ecosystem')
    return self._inner._sort_key(version)  # pylint: disable=protected-access

  def coarse_version(self, version: str) -> str:
    if self._inner is None:
      raise ValueError('TuxCare ecosystem has no resolvable inner ecosystem')
    return self._inner.coarse_version(version)


def _is_valid_inner(suffix: str | None) -> bool:
  """Reject empty suffix and nested TuxCare."""
  if not suffix:
    return False
  return suffix.partition(':')[0] != _TUXCARE

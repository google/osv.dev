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

  The caller (typically ``_ecosystems.get``) is responsible for resolving
  and passing in the inner ecosystem helper. A bare "TuxCare" or a nested
  "TuxCare:TuxCare:..." is malformed; instances built without a resolved
  inner raise ValueError when sort/coarse methods are invoked.
  """

  def __init__(self, suffix: str | None, inner: OrderedEcosystem | None = None):
    super().__init__(suffix)
    self.inner = inner

  @staticmethod
  def is_valid_suffix(suffix: str | None) -> bool:
    """Reject empty suffix and nested TuxCare."""
    if not suffix:
      return False
    return suffix.partition(':')[0] != _TUXCARE

  def _sort_key(self, version: str) -> Any:
    if self.inner is None:
      raise ValueError('TuxCare ecosystem has no resolvable inner ecosystem')
    return self.inner._sort_key(version)  # pylint: disable=protected-access

  def coarse_version(self, version: str) -> str:
    if self.inner is None:
      raise ValueError('TuxCare ecosystem has no resolvable inner ecosystem')
    return self.inner.coarse_version(version)

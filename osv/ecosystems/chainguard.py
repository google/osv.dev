# Copyright 2024 Google LLC
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
"""Chainguard ecosystem helper."""

from typing import List, Optional

from osv.ecosystems.helper_base import Ecosystem
from ..third_party.univers.alpine import AlpineLinuxVersion


class Chainguard(Ecosystem):
  """Chainguard packages ecosystem"""

  def sort_key(self, version: str) -> AlpineLinuxVersion:
    # Chainguard uses `apk` package format
    if not AlpineLinuxVersion.is_valid(version):
      # If version is not valid, it is most likely an invalid input
      # version then sort it to the last/largest element
      return AlpineLinuxVersion('999999')
    return AlpineLinuxVersion(version)

  def enumerate_versions(self,
                         package: str,
                         introduced: str,
                         fixed: Optional[str] = None,
                         last_affected: Optional[str] = None,
                         limits: Optional[List[str]] = None) -> List[str]:
    raise NotImplementedError('Ecosystem helper does not support enumeration')

  @property
  def supports_comparing(self) -> bool:
    return True

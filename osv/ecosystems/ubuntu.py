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
"""Ubuntu ecosystem helper."""

from ..third_party.univers.debian import Version as UbuntuVersion
from ..third_party.univers.debian import compare_versions

from .helper_base import Ecosystem

class Ubuntu(Ecosystem):
  """Ubuntu ecosystem"""

  def supports_comparing(self):
    return True

  def sort_key(self, version):
    if not UbuntuVersion.is_valid(version):
      return UbuntuVersion(999999, 999999)
    return UbuntuVersion.from_string(version)

  def enumerate_versions(self,
                         package,
                         introduced,
                         fixed=None,
                         last_affected=None,
                         limits=None):
    raise NotImplementedError('Ecosystem helper does not support enumeration')

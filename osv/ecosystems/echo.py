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

from .debian import DPKG
from .ecosystems_base import OrderedEcosystem
from .pypi import PyPI


class Echo(OrderedEcosystem):
  """Echo container security ecosystem.

  Echo provides secured packages across multiple ecosystems:
  - Echo        - Debian-based packages (dpkg versioning)
  - Echo:PyPI   - Python packages (PyPI/PEP 440 versioning)
  """

  def _delegate(self) -> OrderedEcosystem:
    if self.suffix and self.suffix.lower() == 'pypi':
      return PyPI()
    return DPKG()

  def _sort_key(self, version: str):
    return self._delegate()._sort_key(version)  # pylint: disable=protected-access

  def coarse_version(self, version: str) -> str:
    return self._delegate().coarse_version(version)

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
"""AlmaLinux ecosystem helper tests."""

import unittest
from .. import ecosystems


class RockyLinuxEcosystemTest(unittest.TestCase):
  """Almalinux ecosystem helper tests."""

  def test_alma_linux(self):
    ecosystem = ecosystems.get('AlmaLinux')
    self.assertGreater(
        ecosystem.sort_key("9.27-15.el8_10"),
        ecosystem.sort_key("9.27-13.el8_10"))
    self.assertGreater(
        ecosystem.sort_key("9.27-15.el8_10"), ecosystem.sort_key("0"))
    self.assertGreater(
        ecosystem.sort_key("3:2.1.10-1.module_el8.10.0+3858+6ad51f9f"),
        ecosystem.sort_key("3:2.1.10-1.module_el8.10.0+3845+87b84552"))

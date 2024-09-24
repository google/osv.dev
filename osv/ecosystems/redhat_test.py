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
"""Red Hat Linux ecosystem helper tests."""

import unittest
from .. import ecosystems


class RedHatEcosystemTest(unittest.TestCase):
  """Red Hat Linux ecosystem helper tests."""

  def test_redhat(self):
    """Test sort_key"""
    ecosystem = ecosystems.get('Red Hat')
    self.assertEqual('Red Hat', ecosystem.name)
    self.assertGreater(
        ecosystem.sort_key('0:0.2.6-20.module+el8.9.0+1420+91577025'),
        ecosystem.sort_key('0:0.0.99.4-5.module+el8.9.0+1445+07728297'))
    self.assertGreater(
        ecosystem.sort_key('0:0.2.6-20.module+el8.9.0+1420+91577025'),
        ecosystem.sort_key('0'))
    self.assertGreater(
        ecosystem.sort_key('2:1.14.3-2.module+el8.10.0+1815+5fe7415e'),
        ecosystem.sort_key('2:1.10.3-1.module+el8.10.0+1815+5fe7415e'))
    self.assertLess(ecosystem.sort_key('invalid'), ecosystem.sort_key('0'))

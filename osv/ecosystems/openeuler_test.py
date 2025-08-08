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
"""openEuler ecosystem helper tests."""

import unittest
from .. import ecosystems


class OpenEulerEcosystemTest(unittest.TestCase):
  """openEuler ecosystem helper tests."""

  def test_openeuler(self):
    """Test sort key"""
    ecosystem = ecosystems.get('openEuler')
    self.assertEqual('openEuler', ecosystem.name)
    self.assertGreater(
        ecosystem.sort_key("1.2.3-1.oe2203"),
        ecosystem.sort_key("1.2.2-1.oe2203"))
    self.assertGreater(
        ecosystem.sort_key("2.0.0-1.oe2203"), ecosystem.sort_key("0"))
    self.assertGreater(
        ecosystem.sort_key("1.2.3-2.oe2203"),
        ecosystem.sort_key("1.2.3-1.oe2203"))
    self.assertLess(
        ecosystem.sort_key("1.2.2-1.oe2203"),
        ecosystem.sort_key("1.2.3-1.oe2203"))
    self.assertEqual(
        ecosystem.sort_key("1.2.3-1.oe2203"),
        ecosystem.sort_key("1.2.3-1.oe2203"))
    self.assertLess(ecosystem.sort_key('invalid'), ecosystem.sort_key('0'))

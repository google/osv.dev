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
"""Mageia ecosystem helper tests."""

import unittest
from .. import ecosystems


class MageiaEcosystemTest(unittest.TestCase):
  """Mageia ecosystem helper tests."""

  def test_mageia(self):
    """Test sort_key"""
    ecosystem = ecosystems.get('Mageia')
    self.assertEqual('Mageia', ecosystem.name)
    self.assertGreater(
        ecosystem.sort_key('3.2.7-1.2.mga9'),
        ecosystem.sort_key('3.2.7-1.mga9'))
    self.assertGreater(
        ecosystem.sort_key('3.2.7-1.2.mga9'), ecosystem.sort_key('0'))
    self.assertLess(ecosystem.sort_key('invalid'), ecosystem.sort_key('0'))

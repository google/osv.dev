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
"""SUSE ecosystem helper tests."""

import unittest
from .. import ecosystems


class SUSEEcosystemTest(unittest.TestCase):
  """SUSE ecosystem helper tests."""

  def test_suse(self):
    """Test sort key"""
    ecosystem = ecosystems.get('SUSE')
    self.assertGreater(
        ecosystem.sort_key("2.38.5-150400.4.34.2"),
        ecosystem.sort_key("2.37.5-150400.4.34.2"))
    self.assertGreater(
        ecosystem.sort_key("2.0.8-4.8.2"), ecosystem.sort_key("0"))
    self.assertGreater(
        ecosystem.sort_key("2.0.8_k4.12.14_10.118-4.8.2"),
        ecosystem.sort_key("2.0.8-4.8.2"))
    self.assertLess(
        ecosystem.sort_key("1.86-150100.7.23.11"),
        ecosystem.sort_key("2.86-150100.7.23.1"))
    self.assertEqual(
        ecosystem.sort_key("2.0.8-4.8.2"),
        ecosystem.sort_key("2.0.8-4.8.2"))

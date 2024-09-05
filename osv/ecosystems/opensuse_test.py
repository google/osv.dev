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
"""openSUSE ecosystem helper tests."""

import unittest
from .. import ecosystems


class openSUSEEcosystemTest(unittest.TestCase):
  """openSUSE ecosystem helper tests."""

  def test_suse(self):
    """Test sort key"""
    ecosystem = ecosystems.get('openSUSE')
    self.assertGreater(
        ecosystem.sort_key("4.2-lp151.4.3.1"),
        ecosystem.sort_key("1.5.1-lp151.4.3.1"))
    self.assertGreater(
        ecosystem.sort_key("4.9.6-bp152.2.3.1"), ecosystem.sort_key("0"))
    self.assertGreater(
        ecosystem.sort_key("6.2.8-bp156.2.3.1"),
        ecosystem.sort_key("6.2.8-bp156"))
    self.assertLess(
        ecosystem.sort_key("0.4.6-15.8"),
        ecosystem.sort_key("1.4.6-15.8"))
    self.assertEqual(
        ecosystem.sort_key("6.2.8-bp156.2.3.1"),
        ecosystem.sort_key("6.2.8-bp156.2.3.1"))

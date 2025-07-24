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
"""Alpaquita ecosystem helper tests."""

import unittest
from .. import ecosystems


class AlpaquitaEcosystemTest(unittest.TestCase):
  """Alpaquita ecosystem helper tests."""

  def test_alpaquita(self):
    """Test sort key"""
    ecosystem = ecosystems.get('Alpaquita')
    # Should not throw exception
    ecosystem.sort_key('1.9.5p2')
    ecosystem.sort_key('1.9.5p2-r0')

    self.assertGreater(
        ecosystem.sort_key('1.9.5p3'), ecosystem.sort_key('1.9.5p2'))
    self.assertGreater(
        ecosystem.sort_key('1.9.5p1'), ecosystem.sort_key('1.9.5'))

    self.assertGreater(
        ecosystem.sort_key('2.78c-r0'), ecosystem.sort_key('2.78a-r1'))

    self.assertGreater(
        ecosystem.sort_key('1.13.2-r0'), ecosystem.sort_key('1.13.2_alpha'))

    # Check invalid version handle.
    # According to alpaquita.py, invalid versions are sorted to the end.
    # '1-0-0' is considered invalid by AlpineLinuxVersion.
    self.assertGreater(
        ecosystem.sort_key('1-0-0'), ecosystem.sort_key('1.13.2-r0'))

    self.assertEqual(
        ecosystem.sort_key('1.13.2-r0'), ecosystem.sort_key('1.13.2-r0'))

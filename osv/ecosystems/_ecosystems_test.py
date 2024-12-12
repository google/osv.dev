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
"""Ecosystem helper tests."""

import unittest
from .. import ecosystems


class EcosystemTest(unittest.TestCase):
  """Ecosystem helper tests."""

  def test_add_matching_ecosystems(self):
    """Test sort key"""
    # Test Ubuntu
    ubuntu_ecosystem = {
        'Ubuntu', 'Ubuntu:20.04:LTS', 'Ubuntu:22.04:LTS', 'Ubuntu:24.04:LTS',
        'Ubuntu:24.10', 'Ubuntu:Pro:14.04:LTS', 'Ubuntu:Pro:16.04:LTS',
        'Ubuntu:Pro:18.04:LTS'
    }
    actual_output = list(ecosystems.add_matching_ecosystems(ubuntu_ecosystem))
    expected_output = [
        'Ubuntu', 'Ubuntu:14.04', 'Ubuntu:16.04', 'Ubuntu:18.04',
        'Ubuntu:20.04', 'Ubuntu:20.04:LTS', 'Ubuntu:22.04', 'Ubuntu:22.04:LTS',
        'Ubuntu:24.04', 'Ubuntu:24.04:LTS', 'Ubuntu:24.10',
        'Ubuntu:Pro:14.04:LTS', 'Ubuntu:Pro:16.04:LTS', 'Ubuntu:Pro:18.04:LTS'
    ]
    actual_output.sort()
    self.assertEqual(list(actual_output), expected_output)

    #Test Debian (it should be no change)
    debian_ecosystem = {'Debian', 'Debian:11', 'Debian:12', 'Debian:13'}
    actual_output = list(ecosystems.add_matching_ecosystems(debian_ecosystem))
    expected_output = ['Debian', 'Debian:11', 'Debian:12', 'Debian:13']
    actual_output.sort()
    self.assertEqual(list(actual_output), expected_output)

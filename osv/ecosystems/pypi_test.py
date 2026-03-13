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
"""PyPI ecosystem helper tests."""

import vcr.unittest
import warnings

from .. import ecosystems


class PyPIEcosystemTest(vcr.unittest.VCRTestCase):
  """PyPI ecosystem helper tests."""

  def test_next_version(self):
    """Test next_version."""
    ecosystem = ecosystems.get('PyPI')
    with warnings.catch_warnings():
      # Filter the DeprecationWarning from next_version
      warnings.filterwarnings('ignore', 'Avoid using this method')
      self.assertEqual('1.36.0rc1', ecosystem.next_version('grpcio', '1.35.0'))
      self.assertEqual('1.36.1', ecosystem.next_version('grpcio', '1.36.0'))
      self.assertEqual('0.3.0', ecosystem.next_version('grpcio', '0'))
      with self.assertRaises(ecosystems.EnumerateError):
        ecosystem.next_version('doesnotexist123456', '1')

  def test_sort_key(self):
    """Test sort_key"""
    ecosystem = ecosystems.get('PyPI')
    self.assertGreater(ecosystem.sort_key('2.0.0'), ecosystem.sort_key('1.0.0'))
    self.assertLess(ecosystem.sort_key('0'), ecosystem.sort_key('legacy'))

    # Check the 0 sentinel value.
    self.assertLess(ecosystem.sort_key('0'), ecosystem.sort_key('0.dev0'))

    # Check >= / <= methods
    self.assertGreaterEqual(
        ecosystem.sort_key('1.10.0'), ecosystem.sort_key('1.2.0'))
    self.assertLessEqual(
        ecosystem.sort_key('1.2.0'), ecosystem.sort_key('1.10.0'))

  def test_coarse_version(self):
    """Test coarse_version"""
    ecosystem = ecosystems.get('PyPI')
    self.assertEqual('00:00000001.00000002.00000003',
                     ecosystem.coarse_version('1.2.3'))
    self.assertEqual('00:00002020.00000000.00000000',
                     ecosystem.coarse_version('0!2020.post1'))
    self.assertEqual('02:00000001.00000002.00000003',
                     ecosystem.coarse_version('2!1.2.3'))
    self.assertEqual('99:99999999.99999999.99999999',
                     ecosystem.coarse_version('100!1.0.0'))
    self.assertEqual('00:00000000.00000000.00000000',
                     ecosystem.coarse_version('1.foobar'))

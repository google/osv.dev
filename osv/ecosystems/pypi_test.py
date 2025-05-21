# Copyright 2021 Google LLC
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

from .. import ecosystems


class PyPIEcosystemTest(vcr.unittest.VCRTestCase):
  """PyPI ecosystem helper tests."""

  def test_next_version(self):
    """Test next_version."""
    ecosystem = ecosystems.get('PyPI')
    self.assertEqual('1.36.0rc1', ecosystem.next_version('grpcio', '1.35.0'))
    self.assertEqual('1.36.1', ecosystem.next_version('grpcio', '1.36.0'))
    self.assertEqual('0.3.0', ecosystem.next_version('grpcio', '0'))
    with self.assertRaises(ecosystems.EnumerateError):
      ecosystem.next_version('doesnotexist123456', '1')

  def test_sort_key(self):
    """Test sort_key"""
    ecosystem = ecosystems.get('PyPI')
    self.assertGreater(ecosystem.sort_key('2.0.0'), ecosystem.sort_key('1.0.0'))
    self.assertLess(ecosystem.sort_key('invalid'), ecosystem.sort_key('0'))

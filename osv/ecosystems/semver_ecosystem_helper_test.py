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
"""SemVer-based ecosystem helper tests."""

import unittest
import warnings

from . import semver_ecosystem_helper
from .. import ecosystems


class SemVerEcosystemTest(unittest.TestCase):
  """SemVer ecosystem helper tests."""

  def test_next_version(self):
    """Test next_version."""
    ecosystem = ecosystems.get('Go')
    with warnings.catch_warnings():
      # Filter the DeprecationWarning from next_version
      warnings.filterwarnings('ignore', 'Avoid using this method')
      self.assertEqual('1.0.1-0', ecosystem.next_version('blah', '1.0.0'))
      self.assertEqual('1.0.0-pre.0',
                       ecosystem.next_version('blah', '1.0.0-pre'))

  def test_sort_key(self):
    """Test sort_key"""
    ecosystem = semver_ecosystem_helper.SemverLike('')
    # Check the 0 sentinel value
    self.assertLess(ecosystem.sort_key('0'), ecosystem.sort_key('0.0.0-0.0'))

    # Check invalid version
    invalid_key = ecosystem.sort_key('invalid')
    valid_key = ecosystem.sort_key('1.0.0')
    # Invalid versions should be greater than valid versions
    self.assertLess(valid_key, invalid_key)
    self.assertGreater(invalid_key, valid_key)
    # Invalid versions should be equal to other invalid versions (for stability)
    self.assertEqual(invalid_key, ecosystem.sort_key('also-invalid'))

  def test_coarse_version(self):
    """Test coarse_version"""
    ecosystem = semver_ecosystem_helper.SemverLike('')
    self.assertEqual('00:00000000.00000000.00000000',
                     ecosystem.coarse_version('0'))
    self.assertEqual('00:00000001.00000002.00000003',
                     ecosystem.coarse_version('1.2.3'))
    self.assertEqual('00:00000010.00000020.00000030',
                     ecosystem.coarse_version('10.20.30-alpha.1'))
    self.assertEqual('00:00000000.00000002.00000000',
                     ecosystem.coarse_version('0.2.0+a'))
    self.assertEqual('00:00000000.00000000.00000099',
                     ecosystem.coarse_version('0.0.99-pre+b'))
    self.assertEqual('00:00000002.99999999.99999999',
                     ecosystem.coarse_version('2.100000000.1'))

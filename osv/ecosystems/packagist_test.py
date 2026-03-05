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
"""Packagist ecosystem helper tests."""

import os
import vcr.unittest

from .. import ecosystems


class PackagistEcosystemTest(vcr.unittest.VCRTestCase):
  """Packagist ecosystem helper tests."""
  _TEST_DATA_DIR = os.path.join(
      os.path.dirname(os.path.abspath(__file__)), 'testdata')

  def test_coarse_version(self):
    """Test coarse_version."""
    ecosystem = ecosystems.get('Packagist')
    self.assertEqual('00:00000001.00000002.00000003',
                     ecosystem.coarse_version('1.2.3'))
    self.assertEqual('00:00000001.00000000.00000000',
                     ecosystem.coarse_version('1.0.0-alpha'))
    self.assertEqual('00:00000001.00000000.00000000',
                     ecosystem.coarse_version('1.0.0-p1'))
    self.assertEqual('00:00000004.00000003.00000002',
                     ecosystem.coarse_version('4.3-2RC1'))
    self.assertEqual('00:00000001.00000002.00000003',
                     ecosystem.coarse_version('1+.+2-_-3'))
    self.assertEqual('00:00000008.99999999.99999999',
                     ecosystem.coarse_version('8.p2'))
    self.assertEqual('00:99999999.99999999.99999999',
                     ecosystem.coarse_version('pl'))

  def test_packagist(self):
    """Test Packagist."""
    ecosystem = ecosystems.get('Packagist')
    self.assertLess(ecosystem.sort_key('string'), ecosystem.sort_key('0.0'))
    self.assertLess(
        ecosystem.sort_key('4.3-2RC1'), ecosystem.sort_key('4.3-2RC2'))
    self.assertGreater(
        ecosystem.sort_key('4.3-2RC2'), ecosystem.sort_key('4.3-2beta5'))
    self.assertGreater(
        ecosystem.sort_key('4.3-2'), ecosystem.sort_key('4.3-2beta1'))
    self.assertGreater(ecosystem.sort_key('1.0.0'), ecosystem.sort_key('1.0'))
    self.assertEqual(
        ecosystem.sort_key('1.0.0rc2'), ecosystem.sort_key('1.0.0.rc2'))

    # Check the 0 sentinel value.
    self.assertLess(ecosystem.sort_key('0'), ecosystem.sort_key('0-a'))

    # Check >= / <= methods
    self.assertGreaterEqual(
        ecosystem.sort_key('1.10-2RC1'), ecosystem.sort_key('1.2-2RC1'))
    self.assertLessEqual(
        ecosystem.sort_key('1.2-2RC1'), ecosystem.sort_key('1.10-2RC1'))

    enumerated_versions = ecosystem.enumerate_versions('neos/neos', '3.3.0',
                                                       '4.4.0')
    self.assertIn('4.3.19', enumerated_versions)
    self.assertIn('4.2.18', enumerated_versions)
    self.assertIn('3.3.1', enumerated_versions)
    self.assertIn('3.3.0', enumerated_versions)

    with open(os.path.join(self._TEST_DATA_DIR,
                           'packagist_test_cases.txt')) as file:
      for line in file.readlines():
        if line.startswith('//') or line.isspace():
          continue
        pieces = line.strip('\n').split(' ')
        v1 = ecosystem.sort_key(pieces[0])
        v2 = ecosystem.sort_key(pieces[2])
        sort_value = (v1 > v2) - (v1 < v2)

        if pieces[1] == '<':
          expected_value = -1
        elif pieces[1] == '=':
          expected_value = 0
        elif pieces[1] == '>':
          expected_value = 1
        else:
          raise RuntimeError('Input not expected: ' + pieces[1])

        self.assertEqual(expected_value, sort_value, pieces)

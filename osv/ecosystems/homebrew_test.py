# Copyright 2026 Google LLC
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
"""Homebrew ecosystem helper tests.

Comparison cases are taken from
https://github.com/Homebrew/brew/blob/HEAD/Library/Homebrew/test/version_spec.rb
plus PkgVersion `_N` revision-suffix cases.
"""

import unittest

from .. import ecosystems
from .homebrew import HomebrewPkgVersion


class HomebrewVersionCompareTest(unittest.TestCase):
  """Homebrew Version#<=> parity tests."""

  # (a, op, b) where op is '<', '>' or '=='.
  _cases = [
      # basic ordering
      ('0.1', '<', '0.2'),
      ('1.2.3', '>', '1.2.2'),
      ('1.2.4', '<', '1.2.4.1'),
      # prerelease markers sort below the release
      ('1.2.3', '>', '1.2.3alpha4'),
      ('1.2.3', '>', '1.2.3beta2'),
      ('1.2.3', '>', '1.2.3rc3'),
      ('1.2.3alpha', '<', '1.2.3'),
      # bare trailing letter is a StringToken, sorts above the release
      ('1.2.3', '<', '1.2.3a'),
      # patch marker sorts above the release
      ('1.2.3', '<', '1.2.3-p34'),
      ('1.2.3-p34', '>', '1.2.3'),
      ('1.2.3-p34', '==', '1.2.3-P34'),
      ('1.2.3-p34', '>', '1.2.3-p33'),
      ('1.2.3-p34', '<', '1.2.3-p35'),
      ('1.2.3-p34', '>', '1.2.3-p9'),
      # alpha
      ('1.2.3alpha4', '>', '1.2.3alpha3'),
      ('1.2.3alpha4', '<', '1.2.3alpha5'),
      ('1.2.3alpha4', '<', '1.2.3alpha10'),
      ('1.2.3alpha4', '<', '1.2.3beta2'),
      ('1.2.3alpha4', '<', '1.2.3rc3'),
      ('1.2.3alpha4', '<', '1.2.3-p34'),
      # beta
      ('1.2.3beta2', '>', '1.2.3beta1'),
      ('1.2.3beta2', '<', '1.2.3beta10'),
      ('1.2.3beta2', '>', '1.2.3alpha4'),
      ('1.2.3beta2', '<', '1.2.3rc3'),
      ('1.2.3beta2', '<', '1.2.3-p34'),
      # pre
      ('1.2.3pre9', '>', '1.2.3pre8'),
      ('1.2.3pre9', '<', '1.2.3pre10'),
      ('1.2.3pre3', '>', '1.2.3alpha4'),
      ('1.2.3pre3', '>', '1.2.3beta5'),
      ('1.2.3pre3', '<', '1.2.3rc2'),
      ('1.2.3pre3', '<', '1.2.3'),
      ('1.2.3pre3', '<', '1.2.3-p2'),
      # rc
      ('1.2.3rc3', '>', '1.2.3rc2'),
      ('1.2.3rc3', '<', '1.2.3rc10'),
      ('1.2.3rc3', '>', '1.2.3beta2'),
      ('1.2.3rc3', '<', '1.2.3-p34'),
      # post
      ('1.2.3.post34', '>', '1.2.3.post33'),
      ('1.2.3.post34', '<', '1.2.3.post35'),
      ('1.2.3.post34', '>', '1.2.3rc35'),
      ('1.2.3.post34', '>', '1.2.3alpha35'),
      ('1.2.3.post34', '>', '1.2.3'),
      # zero-skip: unevenly-padded versions align
      ('2.1.0-p194', '<', '2.1-p195'),
      ('2.1-p195', '>', '2.1.0-p194'),
      ('2.1-p194', '<', '2.1.0-p195'),
      ('2.1.0-p195', '>', '2.1-p194'),
      ('2-p194', '<', '2.1-p195'),
      # PkgVersion revision suffix
      ('1.81.6_5', '<', '1.81.6_6'),
      ('1.81.6_6', '<', '1.82.0'),
      ('1.81.6', '<', '1.81.6_1'),
      ('1.81.6_0', '==', '1.81.6'),
      ('6.0_8', '>', '6.0_6'),
      ('0.12.20_1', '>', '0.12.20'),
  ]

  def test_ordering(self):
    """Compare each pair and its reverse."""
    for a, op, b in self._cases:
      with self.subTest(f'{a} {op} {b}'):
        va, vb = HomebrewPkgVersion(a), HomebrewPkgVersion(b)
        if op == '<':
          self.assertLess(va, vb)
          self.assertGreater(vb, va)
        elif op == '>':
          self.assertGreater(va, vb)
          self.assertLess(vb, va)
        else:
          self.assertEqual(va, vb)
          self.assertEqual(vb, va)


class HomebrewEcosystemTest(unittest.TestCase):
  """Homebrew OrderedEcosystem tests."""

  def setUp(self):
    self.ecosystem = ecosystems.get('Homebrew')

  def test_registered(self):
    self.assertIsNotNone(self.ecosystem)

  def test_sort_key(self):
    self.assertLess(
        self.ecosystem.sort_key('1.81.6_5'),
        self.ecosystem.sort_key('1.81.6_6'))
    self.assertLess(
        self.ecosystem.sort_key('0'), self.ecosystem.sort_key('0.12.20_1'))
    self.assertTrue(self.ecosystem.sort_key('').is_invalid)

  def test_sort_versions(self):
    versions = ['1.82.0', '1.81.6_6', '1.81.6', '1.81.6_5', '1.81.6rc1']
    self.ecosystem.sort_versions(versions)
    self.assertEqual(versions,
                     ['1.81.6rc1', '1.81.6', '1.81.6_5', '1.81.6_6', '1.82.0'])

  def test_coarse_version(self):
    """Test coarse_version output and local monotonicity."""
    self.assertEqual(
        self.ecosystem.coarse_version('1.81.6_6'),
        '00:00000001.00000081.00000006')
    self.assertEqual(
        self.ecosystem.coarse_version('6.0_8'), '00:00000006.00000000.00000000')
    # Prerelease/patch markers truncate; must not exceed the release's coarse.
    self.assertLessEqual(
        self.ecosystem.coarse_version('1.2.3rc1'),
        self.ecosystem.coarse_version('1.2.3'))
    self.assertLessEqual(
        self.ecosystem.coarse_version('1.2.3'),
        self.ecosystem.coarse_version('1.2.3-p34'))


if __name__ == '__main__':
  unittest.main()

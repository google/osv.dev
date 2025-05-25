# Copyright 2023 Google LLC
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
#
# Many tests are ported from
# https://github.com/dart-lang/pub_semver/blob/master/test/version_test.dart
"""Pub version parser tests."""

import unittest
import vcr.unittest

from . import pub
from .. import ecosystems


class PubVersionTest(unittest.TestCase):
  """Pub version tests."""

  def setUp(self):
    self.maxDiff = None  # pylint: disable=invalid-name

  def test_comparison(self):
    """Test version comparisons."""
    # A correctly sorted list of versions.
    versions = [
        '1.0.0-alpha', '1.0.0-alpha.1', '1.0.0-beta.2', '1.0.0-beta.11',
        '1.0.0-rc.1', '1.0.0-rc.1+build.1', '1.0.0', '1.0.0+0.3.7',
        '1.3.7+build', '1.3.7+build.2.b8f12d7', '1.3.7+build.11.e0f985a',
        '2.0.0', '2.1.0', '2.2.0', '2.11.0', '2.11.1'
    ]

    for i, a_str in enumerate(versions):
      for j, b_str in enumerate(versions):
        a = pub.Version.from_string(a_str)
        b = pub.Version.from_string(b_str)
        self.assertEqual(a < b, i < j)
        self.assertEqual(a == b, i == j)

  def test_equality(self):
    """Test version equality."""

    def check_version_equals(v1, v2):
      self.assertEqual(pub.Version.from_string(v1), pub.Version.from_string(v2))

    check_version_equals('01.2.3', '1.2.3')
    check_version_equals('1.02.3', '1.2.3')
    check_version_equals('1.2.03', '1.2.3')
    check_version_equals('1.2.3-01', '1.2.3-1')
    check_version_equals('1.2.3+01', '1.2.3+1')

  def test_parse(self):
    """Test versions can be parsed."""
    pub.Version.from_string('0.0.0')
    pub.Version.from_string('12.34.56')
    pub.Version.from_string('1.2.3-alpha.1')
    pub.Version.from_string('1.2.3-x.7.z-92')
    pub.Version.from_string('1.2.3+build.1')
    pub.Version.from_string('1.2.3+x.7.z-92')
    pub.Version.from_string('1.0.0-rc-1+build-1')
    # Tests invalid versions
    pub.Version.from_string('3.4.0rc3-invalid')

  def test_empty_identifier(self):
    """Test parsing versions with empty identifiers.

    Although it's unlikely that it was intentional, SemVer 2.0.0-rc.1 does not
    explicitly disallow this case. Not sure if Pub even allows it.

    This test is probably unnecessary."""

    pub.Version.from_string('1.0.0-a..b')
    pub.Version.from_string('1.0.0-.a.b')
    pub.Version.from_string('1.0.0-a.b.')
    pub.Version.from_string('1.0.0+a..b')
    pub.Version.from_string('1.0.0+.a.b')
    pub.Version.from_string('1.0.0+a.b.')
    pub.Version.from_string('1.0.0-+')
    pub.Version.from_string('1.0.0-.+.')
    pub.Version.from_string('1.0.0-....+....')

    # Basic test for ordering.
    v_empty = pub.Version.from_string('1.0.0-a..b')
    v_number = pub.Version.from_string('1.0.0-a.0.b')
    v_str = pub.Version.from_string('1.0.0-a.a.b')
    self.assertLess(v_number, v_empty)
    self.assertLess(v_empty, v_str)

    # note(michaelkedar):
    # The implementation incorrectly assumes "1.0.0-a..b" == "1.0.0-a.-.b"
    # I have decided that this extreme edge case is not worth fixing.


class PubEcosystemTest(vcr.unittest.VCRTestCase):
  """Pub ecosystem helper tests."""

  def test_next_version(self):
    """Test next_version."""
    ecosystem = ecosystems.get('Pub')

    self.assertEqual('2.0.0-nullsafety.0',
                     ecosystem.next_version('pub_semver', '1.4.4'))
    self.assertEqual('2.0.0',
                     ecosystem.next_version('pub_semver', '2.0.0-nullsafety.0'))
    self.assertEqual('2.1.0', ecosystem.next_version('pub_semver', '2.0.0'))
    self.assertEqual('2.1.1', ecosystem.next_version('pub_semver', '2.1.0'))

    # Versions with pre-release and build suffixes.
    self.assertEqual('3.0.0-alpha+2',
                     ecosystem.next_version('mockito', '3.0.0-alpha'))
    self.assertEqual('3.0.0-alpha+3',
                     ecosystem.next_version('mockito', '3.0.0-alpha+2'))
    self.assertEqual('3.0.0-beta',
                     ecosystem.next_version('mockito', '3.0.0-alpha+5'))
    self.assertEqual('3.0.0', ecosystem.next_version('mockito', '3.0.0-beta+3'))
    self.assertEqual('4.1.1+1', ecosystem.next_version('mockito', '4.1.1'))
    self.assertEqual('4.1.2', ecosystem.next_version('mockito', '4.1.1+1'))

    # Version marked as retracted (go_router 4.2.1)
    self.assertEqual('4.2.1', ecosystem.next_version('go_router', '4.2.0'))
    self.assertEqual('4.2.2', ecosystem.next_version('go_router', '4.2.1'))


if __name__ == '__main__':
  unittest.main()

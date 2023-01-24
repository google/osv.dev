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

from . import pub


class PubTest(unittest.TestCase):
  """Pub version tests."""

  def setUp(self):
    self.maxDiff = None  # pylint: disable=invalid-name

  def test_comparison(self):
    """Test version comparisons."""
    # A correctly sorted list of versions.
    versions = [
      '1.0.0-alpha',
      '1.0.0-alpha.1',
      '1.0.0-beta.2',
      '1.0.0-beta.11',
      '1.0.0-rc.1',
      '1.0.0-rc.1+build.1',
      '1.0.0',
      '1.0.0+0.3.7',
      '1.3.7+build',
      '1.3.7+build.2.b8f12d7',
      '1.3.7+build.11.e0f985a',
      '2.0.0',
      '2.1.0',
      '2.2.0',
      '2.11.0',
      '2.11.1'
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
    
    check_version_equals("01.2.3", "1.2.3")
    check_version_equals("1.02.3", "1.2.3")
    check_version_equals("1.2.03", "1.2.3")
    check_version_equals("1.2.3-01", "1.2.3-1")
    check_version_equals("1.2.3+01", "1.2.3+1")

if __name__ == '__main__':
  unittest.main()

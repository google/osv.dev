"""Maven version parser tests."""
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
#
# pylint: disable=line-too-long
# Many tests are ported from
# https://github.com/apache/maven/blob/c3cf29438e3d65d6ee5c5726f8611af99d9a649a/maven-artifact/src/test/java/org/apache/maven/artifact/versioning/ComparableVersionTest.java.
import unittest

from . import version


class VersionTest(unittest.TestCase):
  """Version tests."""

  def setUp(self):
    self.maxDiff = None  # pylint: disable=invalid-name

  def check_versions_order(self, *versions):
    """Check that our precedence logic matches the expected order."""
    parsed_versions = [version.Version.from_string(v) for v in versions]

    # pylint: disable=consider-using-enumerate
    for i in range(len(parsed_versions)):
      for j in range(i + 1, len(parsed_versions)):
        self.assertLess(
            parsed_versions[i],
            parsed_versions[j],
            msg=f'Expected {versions[i]} < {versions[j]}')
        self.assertGreater(
            parsed_versions[j],
            parsed_versions[i],
            msg=f'Expected {versions[j]} > {versions[i]}')

  def check_versions_equal(self, *versions):
    """Check that the provided versions are equivalent."""
    parsed_versions = [version.Version.from_string(v) for v in versions]

    # pylint: disable=consider-using-enumerate
    for i in range(len(parsed_versions)):
      for j in range(i + 1, len(parsed_versions)):
        self.assertEqual(
            parsed_versions[i],
            parsed_versions[j],
            msg=f'Expected {versions[i]} == {versions[j]}')

  def test_normalize(self):
    """Test version normalization."""
    self.assertEqual('1', str(version.Version.from_string('1.0.0')))
    self.assertEqual('1', str(version.Version.from_string('1.ga')))
    self.assertEqual('1', str(version.Version.from_string('1.final')))
    self.assertEqual('1', str(version.Version.from_string('1.0')))
    self.assertEqual('1', str(version.Version.from_string('1.')))
    self.assertEqual('1', str(version.Version.from_string('1-')))
    self.assertEqual('1-foo', str(version.Version.from_string('1.0.0-foo.0.0')))
    self.assertEqual('1', str(version.Version.from_string('1.0.0-0.0.0')))
    self.assertEqual('1-1.foo-bar-1-baz-0.1',
                     str(version.Version.from_string('1-1.foo-bar1baz-.1')))
    self.assertEqual('1-rc', str(version.Version.from_string('1cr')))
    self.assertEqual('1-a', str(version.Version.from_string('1a')))
    self.assertEqual('1-alpha-1', str(version.Version.from_string('1a1')))
    self.assertEqual('1-beta-1', str(version.Version.from_string('1b1')))
    self.assertEqual('1-c-1', str(version.Version.from_string('1c1')))
    self.assertEqual('1-milestone-1', str(version.Version.from_string('1m1')))
    self.assertEqual('1-1', str(version.Version.from_string('1-ga-1')))

  def test_sort(self):
    """Basic sort tests."""
    # These tests are taken from the spec.
    unsorted = [
        '1',
        '1.1',
        '1-snapshot',
        '1',
        '1-sp',
        '1-foo2',
        '1-foo10',
        '1.foo',
        '1-foo',
        '1-1',
        '1.1',
        '1.ga',
        '1-ga',
        '1-0',
        '1.0',
        '1',
        '1-sp',
        '1-ga',
        '1-sp.1',
        '1-ga.1',
        '1-sp-1',
        '1-ga-1',
        '1-1',
        '1-a1',
        '1-alpha-1',
        '2',
    ]

    sorted_versions = [
        str(v) for v in sorted(
            version.Version.from_string(v) for v in unsorted)
    ]

    self.assertListEqual([
        '1-alpha-1', '1-alpha-1', '1-snapshot', '1', '1', '1', '1', '1', '1',
        '1', '1', '1.foo', '1-.1', '1-sp', '1-sp', '1-sp-1', '1-sp.1', '1-foo',
        '1-foo-2', '1-foo-10', '1-1', '1-1', '1-1', '1.1', '1.1', '2'
    ], sorted_versions)

  def test_versions_qualifiers(self):
    """Test qualifiers."""
    expected = [
        '1-alpha2snapshot', '1-alpha2', '1-alpha-123', '1-beta-2', '1-beta123',
        '1-m2', '1-m11', '1-rc', '1-cr2', '1-rc123', '1-SNAPSHOT', '1', '1-sp',
        '1-sp2', '1-sp123', '1-abc', '1-def', '1-pom-1', '1-1-snapshot', '1-1',
        '1-2', '1-123'
    ]
    self.check_versions_order(*expected)

  def test_versions_number(self):
    """Test numbers."""
    # Taken from Maven's tests.
    expected = [
        '2.0', '2-1', '2.0.a', '2.0.0.a', '2.0.2', '2.0.123', '2.1.0', '2.1-a',
        '2.1b', '2.1-c', '2.1-1', '2.1.0.1', '2.2', '2.123', '11.a2', '11.a11',
        '11.b2', '11.b11', '11.m2', '11.m11', '11', '11.a', '11b', '11c', '11m'
    ]
    self.check_versions_order(*expected)

  def test_versions_order(self):
    """More ordering tests."""
    self.check_versions_order('1', '2')
    self.check_versions_order('1.5', '2')
    self.check_versions_order('1', '2.5')
    self.check_versions_order('1.0', '1.1')
    self.check_versions_order('1.1', '1.2')
    self.check_versions_order('1.0.0', '1.1')
    self.check_versions_order('1.0.1', '1.1')
    self.check_versions_order('1.1', '1.2.0')

    self.check_versions_order('1.0-alpha-1', '1.0')
    self.check_versions_order('1.0-alpha-1', '1.0-alpha-2')
    self.check_versions_order('1.0-alpha-1', '1.0-beta-1')

    self.check_versions_order('1.0-beta-1', '1.0-SNAPSHOT')
    self.check_versions_order('1.0-SNAPSHOT', '1.0')
    self.check_versions_order('1.0-alpha-1-SNAPSHOT', '1.0-alpha-1')

    self.check_versions_order('1.0', '1.0-1')
    self.check_versions_order('1.0-1', '1.0-2')
    self.check_versions_order('1.0.0', '1.0-1')

    self.check_versions_order('2.0-1', '2.0.1')
    self.check_versions_order('2.0.1-klm', '2.0.1-lmn')
    self.check_versions_order('2.0.1', '2.0.1-xyz')

    self.check_versions_order('2.0.1', '2.0.1-123')
    self.check_versions_order('2.0.1-xyz', '2.0.1-123')

  def test_versions_order_mng_5568(self):
    """Regression test for MNG 5568."""
    a = '6.1.0'
    b = '6.1.0rc3'
    c = '6.1H.5-beta'

    self.check_versions_order(b, a)
    self.check_versions_order(b, c)
    self.check_versions_order(a, c)

  def test_versions_order_mng_6572(self):
    """Regression test for MNG 6572."""
    a = '20190126.230843'
    b = '1234567890.12345'
    c = '123456789012345.1H.5-beta'
    d = '12345678901234567890.1H.5-beta'

    self.check_versions_order(a, b)
    self.check_versions_order(b, c)
    self.check_versions_order(a, c)
    self.check_versions_order(c, d)
    self.check_versions_order(b, d)
    self.check_versions_order(a, d)

  def test_versions_equal(self):
    """Test versions that should be considered equal."""
    self.check_versions_equal('1', '1')
    self.check_versions_equal('1', '1.0')
    self.check_versions_equal('1', '1.0.0')
    self.check_versions_equal('1.0', '1.0.0')
    self.check_versions_equal('1', '1-0')
    self.check_versions_equal('1', '1.0-0')
    self.check_versions_equal('1.0', '1.0-0')
    # no separator between number and character
    self.check_versions_equal('1a', '1-a')
    self.check_versions_equal('1a', '1.0-a')
    self.check_versions_equal('1a', '1.0.0-a')
    self.check_versions_equal('1.0a', '1-a')
    self.check_versions_equal('1.0.0a', '1-a')
    self.check_versions_equal('1x', '1-x')
    self.check_versions_equal('1x', '1.0-x')
    self.check_versions_equal('1x', '1.0.0-x')
    self.check_versions_equal('1.0x', '1-x')
    self.check_versions_equal('1.0.0x', '1-x')

    # aliases
    self.check_versions_equal('1ga', '1')
    self.check_versions_equal('1release', '1')
    self.check_versions_equal('1final', '1')
    self.check_versions_equal('1cr', '1rc')

    # special 'aliases' a, b and m for alpha, beta and milestone
    self.check_versions_equal('1a1', '1-alpha-1')
    self.check_versions_equal('1b2', '1-beta-2')
    self.check_versions_equal('1m3', '1-milestone-3')

    # case insensitive
    self.check_versions_equal('1X', '1x')
    self.check_versions_equal('1A', '1a')
    self.check_versions_equal('1B', '1b')
    self.check_versions_equal('1M', '1m')
    self.check_versions_equal('1Ga', '1')
    self.check_versions_equal('1GA', '1')
    self.check_versions_equal('1RELEASE', '1')
    self.check_versions_equal('1release', '1')
    self.check_versions_equal('1RELeaSE', '1')
    self.check_versions_equal('1Final', '1')
    self.check_versions_equal('1FinaL', '1')
    self.check_versions_equal('1FINAL', '1')
    self.check_versions_equal('1Cr', '1Rc')
    self.check_versions_equal('1cR', '1rC')
    self.check_versions_equal('1m3', '1Milestone3')
    self.check_versions_equal('1m3', '1MileStone3')
    self.check_versions_equal('1m3', '1MILESTONE3')

    self.check_versions_equal('1', '01', '001')


if __name__ == '__main__':
  unittest.main()

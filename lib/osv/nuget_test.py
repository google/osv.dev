# Copyright 2022 Google LLC
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
# https://github.com/NuGet/NuGet.Client/blob/dev/test/NuGet.Core.Tests/NuGet.Versioning.Test/VersionComparerTests.cs
"""NuGet version parser tests."""

import unittest

from . import nuget


class NuGetTest(unittest.TestCase):
  """NuGet version tests."""

  def setUp(self):
    self.maxDiff = None  # pylint: disable=invalid-name

  def check_order(self, comparison, first, second):
    """Check order."""
    comparison(
        nuget.Version.from_string(first), nuget.Version.from_string(second))

  def test_equals(self):
    """Test version equals."""
    self.check_order(self.assertEqual, '1.0.0', '1.0.0')
    self.check_order(self.assertEqual, '1.0.0-BETA', '1.0.0-beta')
    self.check_order(self.assertEqual, '1.0.0-BETA+AA', '1.0.0-beta+aa')
    self.check_order(self.assertEqual, '1.0.0-BETA.X.y.5.77.0+AA',
                     '1.0.0-beta.x.y.5.77.0+aa')
    self.check_order(self.assertEqual, '1.0.0', '1.0.0+beta')

    self.check_order(self.assertEqual, '1.0', '1.0.0.0')
    self.check_order(self.assertEqual, '1.0+test', '1.0.0.0')
    self.check_order(self.assertEqual, '1.0.0.1-1.2.A', '1.0.0.1-1.2.a+A')
    self.check_order(self.assertEqual, '1.0.01', '1.0.1.0')

  def test_not_equals(self):
    """Test version not equals."""
    self.check_order(self.assertNotEqual, '1.0', '1.0.0.1')
    self.check_order(self.assertNotEqual, '1.0+test', '1.0.0.1')
    self.check_order(self.assertNotEqual, '1.0.0.1-1.2.A', '1.0.0.1-1.2.a.A+A')
    self.check_order(self.assertNotEqual, '1.0.01', '1.0.1.2')
    self.check_order(self.assertNotEqual, '0.0.0', '1.0.0')
    self.check_order(self.assertNotEqual, '1.1.0', '1.0.0')
    self.check_order(self.assertNotEqual, '1.0.1', '1.0.0')
    self.check_order(self.assertNotEqual, '1.0.0-BETA', '1.0.0-beta2')
    self.check_order(self.assertNotEqual, '1.0.0+AA', '1.0.0-beta+aa')
    self.check_order(self.assertNotEqual, '1.0.0-BETA.X.y.5.77.0+AA',
                     '1.0.0-beta.x.y.5.79.0+aa')

  def test_less(self):
    """Test version less."""
    self.check_order(self.assertLess, '0.0.0', '1.0.0')
    self.check_order(self.assertLess, '1.0.0', '1.1.0')
    self.check_order(self.assertLess, '1.0.0', '1.0.1')
    self.check_order(self.assertLess, '1.999.9999', '2.1.1')
    self.check_order(self.assertLess, '1.0.0-BETA', '1.0.0-beta2')
    self.check_order(self.assertLess, '1.0.0-beta+AA', '1.0.0+aa')
    self.check_order(self.assertLess, '1.0.0-BETA', '1.0.0-beta.1+AA')
    self.check_order(self.assertLess, '1.0.0-BETA.X.y.5.77.0+AA',
                     '1.0.0-beta.x.y.5.79.0+aa')
    self.check_order(self.assertLess, '1.0.0-BETA.X.y.5.79.0+AA',
                     '1.0.0-beta.x.y.5.790.0+abc')

    self.check_order(self.assertLess, '1.0.0', '1.0.0.1')
    self.check_order(self.assertLess, '1.0.0.1-alpha', '1.0.0.1-pre')
    self.check_order(self.assertLess, '1.0.0-pre', '1.0.0.1-alpha')
    self.check_order(self.assertLess, '1.0.0', '1.0.0.1-alpha')
    self.check_order(self.assertLess, '0.9.9.1', '1.0.0')


if __name__ == '__main__':
  unittest.main()
